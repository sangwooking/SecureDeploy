package com.securedeploy.review.dto;

import com.securedeploy.analysis.typescript.ServerAnalysisSnapshot;
import com.securedeploy.risk.model.RiskPriority;
import java.util.*;

/** Read-only interpretation of saved evidence. Never recalculates risk or rewrites a snapshot. */
public record ReviewResultSummary(int schemaVersion,String interpretationVersion,String guidance,String title,String reason,
        int referenceScore,String scoreScope,String legacyDeploymentStatus,String policyAssessment,String policyVersion,
        String riskCalculationStatus,long blockingCount,int importantRuleSignals,
        Integer flowCandidates,Integer declarationCandidates,Integer aiCandidates,String structuralComparison,
        String coverageStatus,Integer discoveredFiles,Integer patternInputFiles,Boolean inventoryComplete,
        List<AnalyzerState> analyzers,String scaStatus,Integer dependenciesAnalyzed,Integer unresolvedDependencies,
        String semanticStatus,boolean authContextObserved,boolean rlsDeclarationsObserved,String runtimeVerification,
        List<String> limitations) {
    public record AnalyzerState(String analyzer,String status,Map<String,Integer> observations) { }

    public static ReviewResultSummary from(SecurityReviewResponse review) {
        var risk=review.riskAssessment();var coverage=review.coverage();var sca=review.sca();var server=review.serverAnalysis();
        var languages=new ArrayList<ServerAnalysisSnapshot>();
        if(server!=null){languages.add(server);if(server.pythonAnalysis()!=null)languages.add(server.pythonAnalysis());}
        var flowIds=new HashSet<String>();boolean flowRecorded=false;
        for(var language:languages)if(language.validatedFindings()!=null){
            flowRecorded=true;language.validatedFindings().forEach(f->flowIds.add(f.sourceType()+":"+f.findingId()));
        }
        if(server!=null&&server.javaAnalysis()!=null){
            flowRecorded=true;list(server.javaAnalysis().findings()).forEach(f->flowIds.add("JAVA:"+f.findingId()));
        }
        var declarationIds=new HashSet<String>();boolean declarationsRecorded=false;
        if(server!=null&&server.deploymentAnalysis()!=null){
            declarationsRecorded=true;list(server.deploymentAnalysis().findings()).forEach(f->declarationIds.add("CONFIG:"+f.findingId()));
        }
        var supabase=server==null?null:server.supabaseAnalysis();
        if(supabase!=null){declarationsRecorded=true;list(supabase.findings()).forEach(f->declarationIds.add("RLS:"+f.findingId()));}
        Integer flows=flowRecorded?flowIds.size():null,declarations=declarationsRecorded?declarationIds.size():null;
        var semantic=review.semanticReview();
        Integer ai=semantic==null?null:list(semantic.candidates()).size();
        String scaStatus=sca==null?"NOT_RECORDED":state(sca.status());
        String coverageStatus=coverage==null||coverage.status()==null?"NOT_RECORDED":coverage.status();
        String policy=risk==null?"NOT_RECORDED":state(risk.prioritizedDeploymentAssessment());
        long blocking=risk==null||risk.prioritySummary()==null?0:risk.prioritySummary().getOrDefault(RiskPriority.BLOCKING,0L);
        int important=(int)list(review.vulnerabilities()).stream().filter(v->v.severity()!=null
                &&Set.of("HIGH","CRITICAL").contains(v.severity().name())).count();
        boolean failed="FAILED".equals(coverageStatus)||risk!=null&&risk.assessmentCoverage()!=null
                &&risk.assessmentCoverage().overall()==com.securedeploy.risk.model.RiskAssessment.Completion.FAILED;
        boolean gaps=coverage==null||!"COMPLETE".equals(coverageStatus)||!coverage.inventoryComplete()
                ||coverage.unsupportedFiles()>0||coverage.failedFiles()>0||coverage.excludedFiles()>0
                ||!Set.of("COMPLETE","NO_MANIFEST").contains(scaStatus)||sca!=null&&sca.summary()!=null&&sca.summary().unresolvedDependencies()>0
                ||risk==null||risk.assessmentCoverage()==null||risk.assessmentCoverage().overall()!=com.securedeploy.risk.model.RiskAssessment.Completion.COMPLETE;
        var analyzerStates=new ArrayList<AnalyzerState>();
        if(coverage!=null)for(var analyzer:list(coverage.analyzers())){
            var status=analyzer.status()==null?"NOT_RECORDED":analyzer.status();
            analyzerStates.add(new AnalyzerState(analyzer.analyzer(),status,analyzer.fileStatuses()==null?Map.of():Map.copyOf(analyzer.fileStatuses())));
            if(!Set.of("COMPLETE","NOT_APPLICABLE").contains(status))gaps=true;
            if("FAILED".equals(status))failed=true;
        }
        String guidance,title,reason;
        if("BLOCKED".equals(policy)||blocking>0){
            guidance="PRIORITY_ACTION_REQUIRED";title="반드시 처리할 문제부터 확인하세요";
            reason="저장된 위험 정책에 배포 전 처리 항목이 있습니다. 높은 참고 점수나 다른 검사 상태가 이 판단을 취소하지 않습니다.";
        }else if(failed){
            guidance="ANALYSIS_INCOMPLETE";title="완료하지 못한 검사를 확인하세요";
            reason="저장된 기록에 분석 실패가 있습니다. 발견 항목이 없어도 검사 성공이나 안전을 뜻하지 않습니다.";
        }else if(important>0||flowIds.size()+declarationIds.size()+(ai==null?0:ai)>0||"REVIEW_REQUIRED".equals(policy)
                ||risk!=null&&risk.prioritySummary()!=null&&risk.prioritySummary().getOrDefault(RiskPriority.REVIEW_REQUIRED,0L)>0){
            guidance="REVIEW_NEEDED";title="보안 근거와 추가 확인 사항을 검토하세요";
            reason="중요한 규칙 경고 또는 별도 검토 후보가 있습니다. 구조·AI 후보는 기존 점수와 위험 정책 판단에 합산되지 않습니다.";
        }else if(gaps||risk==null){
            guidance="SCOPE_REVIEW_NEEDED";title="검사하지 못한 범위를 먼저 확인하세요";
            reason="표시된 경고가 없더라도 검사 범위나 외부 조회 기록이 충분하지 않습니다. 미검사를 취약점 없음으로 해석하지 마세요.";
        }else if("READY_WITH_WARNINGS".equals(policy)){
            guidance="RECOMMENDATIONS_PRESENT";title="저장된 수정 권장 항목을 확인하세요";
            reason="기존 정책의 권장 항목이 있습니다. 정책 판단은 실제 배포 승인이나 전체 보안 인증이 아닙니다.";
        }else{
            guidance="SUPPORTED_RESULTS_RECORDED";title="지원 범위의 검사 결과가 기록됐습니다";
            reason="현재 기록에서 우선 확인할 경고가 없다는 뜻입니다. 운영 환경과 전체 프로젝트의 안전을 보증하지 않습니다.";
        }
        boolean auth=languages.stream().flatMap(l->list(l.authorizationContexts()).stream()).anyMatch(c->
                list(c.checks()).stream().anyMatch(check->Set.of("LOGIN_CONTEXT_REFERENCE","AUTH_DECLARATION").contains(Objects.toString(check.kind(),"UNKNOWN")))
                ||c.details()!=null&&Set.of("DECLARED_LOGIN_REQUIRED","DECLARED_STAFF_REQUIRED","DECLARED_PUBLIC").contains(Objects.toString(c.details().authenticationStatus(),"UNKNOWN")))
                ||supabase!=null&&list(supabase.accesses()).stream().anyMatch(a->a.authorizationEvidence()!=null
                    &&!list(a.authorizationEvidence().authChecks()).isEmpty());
        boolean rls=supabase!=null&&!list(supabase.tables()).isEmpty();
        return new ReviewResultSummary(1,"review-summary-v1",guidance,title,reason,review.securityScore(),"RULE_ENGINE_REFERENCE_ONLY",
                review.deploymentStatus(),policy,risk==null?null:risk.policyVersion(),
                risk==null||risk.assessmentCoverage()==null?"NOT_RECORDED":state(risk.assessmentCoverage().overall()),
                blocking,important,flows,declarations,ai,"NOT_COMPARED",coverageStatus,
                coverage==null?null:coverage.discoveredFiles(),coverage==null?null:coverage.selectedFiles(),
                coverage==null?null:coverage.inventoryComplete(),List.copyOf(analyzerStates),scaStatus,
                sca==null||sca.summary()==null?null:sca.summary().dependenciesAnalyzed(),
                sca==null||sca.summary()==null?null:sca.summary().unresolvedDependencies(),
                semantic==null?"NOT_RECORDED":state(semantic.semanticReviewStatus()),auth,rls,"NOT_PERFORMED",
                List.of("SCORE_IS_NOT_WHOLE_PROJECT_ASSURANCE","STRUCTURAL_CANDIDATES_NOT_INCLUDED_IN_RISK",
                        "PATTERN_CONFIDENCE_IS_NOT_EXPLOIT_PROOF","RUNTIME_AUTHORIZATION_AND_DATABASE_NOT_VERIFIED",
                        "MISSING_HISTORICAL_EVIDENCE_NOT_BACKFILLED"));
    }
    private static <T> List<T> list(List<T> values){return values==null?List.of():values;}
    private static String state(Enum<?> value){return value==null?"NOT_RECORDED":value.name();}
}
