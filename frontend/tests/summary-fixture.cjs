const fixture=require('./result-fixture.cjs');
module.exports=function scenarios(){
  const base=()=>{
    const r=fixture();r.vulnerabilities=[];r.vulnerabilityCount=0;r.semanticReview={...r.semanticReview,semanticReviewStatus:'NOT_REQUESTED',candidates:[],requestCount:0};
    Object.assign(r.riskAssessment,{prioritizedDeploymentAssessment:'READY',codeFindings:[],dependencyFindings:[],reviewRequirements:[],
      prioritySummary:{BLOCKING:0,REVIEW_REQUIRED:0,SHOULD_FIX:0,INFORMATIONAL:0}});
    r.sca={...r.sca,status:'DISABLED',components:[],dependencyVulnerabilities:[],summary:{...r.sca.summary,dependenciesAnalyzed:0,unresolvedDependencies:0}};
    r.coverage={schemaVersion:1,policyVersion:'coverage-v2',status:'PARTIAL',discoveredFiles:8,selectedFiles:6,unsupportedFiles:2,excludedFiles:0,failedFiles:0,inventoryComplete:true,omittedEntries:0,entries:[],
      analyzers:[{analyzer:'SUPABASE_RLS',status:'PARTIAL',scope:'선언만 확인',fileStatuses:{SQL_NOT_RUN:2}}]};
    r.resultSummary={schemaVersion:1,interpretationVersion:'review-summary-v1',guidance:'SCOPE_REVIEW_NEEDED',title:'검사하지 못한 범위를 먼저 확인하세요',reason:'미검사를 취약점 없음으로 해석하지 마세요.',
      referenceScore:100,scoreScope:'RULE_ENGINE_REFERENCE_ONLY',legacyDeploymentStatus:r.deploymentStatus,policyAssessment:'READY',policyVersion:'risk-v1.2',riskCalculationStatus:'COMPLETE',
      blockingCount:0,importantRuleSignals:0,flowCandidates:0,declarationCandidates:0,aiCandidates:0,structuralComparison:'NOT_COMPARED',
      coverageStatus:'PARTIAL',discoveredFiles:8,patternInputFiles:6,inventoryComplete:true,analyzers:r.coverage.analyzers.map(a=>({analyzer:a.analyzer,status:a.status,observations:a.fileStatuses})),
      scaStatus:'DISABLED',dependenciesAnalyzed:0,unresolvedDependencies:0,semanticStatus:'NOT_REQUESTED',authContextObserved:false,rlsDeclarationsObserved:false,runtimeVerification:'NOT_PERFORMED',limitations:[]};
    return r;
  };
  const cases=[];const add=(id,r,expected,view='SUMMARY')=>cases.push({id,result:r,expected,view});
  let r=base();r.serverAnalysis=require('./server-analysis-fixture.cjs')();Object.assign(r.resultSummary,{flowCandidates:1,guidance:'REVIEW_NEEDED',title:'추가 확인 <img src=x onerror=alert(1)>',reason:'구조 후보를 확인하는 합성 응답입니다.'});
  add('perfect-partial-flow',r,['100 / 100','코드 흐름 검토 후보','전체 안전 점수가 아닙니다','일부만 확인']);
  r=base();r.riskAssessment.prioritizedDeploymentAssessment='BLOCKED';r.riskAssessment.prioritySummary.BLOCKING=1;
  r.riskAssessment.dependencyFindings=[{...fixture().riskAssessment.dependencyFindings[0],priority:'BLOCKING'}];
  Object.assign(r.resultSummary,{guidance:'PRIORITY_ACTION_REQUIRED',title:'반드시 처리할 문제부터 확인하세요',policyAssessment:'BLOCKED',blockingCount:1});
  add('sca-blocked',r,['반드시 처리할 문제부터 확인하세요','배포 전 수정 필요','100 / 100']);
  r=base();r.serverAnalysis=require('./server-analysis-fixture.cjs')();r.vulnerabilities=fixture().vulnerabilities;r.riskAssessment.codeFindings=fixture().riskAssessment.codeFindings.map(f=>({...f,priority:'REVIEW_REQUIRED'}));
  Object.assign(r.resultSummary,{flowCandidates:1,guidance:'REVIEW_NEEDED',title:'보안 근거와 추가 확인 사항을 검토하세요',importantRuleSignals:1});
  add('rule-and-flow',r,['규칙 경고','코드 흐름','HIGH'],'REVIEW_REQUIRED');
  r=base();add('no-findings-uninspected',r,['검사하지 못한 범위를 먼저 확인하세요','정책 SQL 분석 미실행','전체 안전 점수가 아닙니다']);
  r=base();r.sca.status='UNAVAILABLE';r.resultSummary.scaStatus='UNAVAILABLE';add('osv-failed',r,['외부 라이브러리 보안','정보를 확인하지 못했어요']);
  r=base();r.resultSummary.authContextObserved=true;add('auth-unknown',r,['로그인 성공이나 리소스 소유권 검증을 뜻하지 않습니다']);
  r=base();r.resultSummary.rlsDeclarationsObserved=true;add('rls-runtime-unknown',r,['운영 DB 적용과 실제 역할은 미확인']);
  r=base();const html={...fixture().vulnerabilities[0],ruleId:'REACT_DANGEROUS_HTML',category:'CLIENT_XSS',analysisNote:'HTML_CONTEXT=UNRESOLVED_HTML; SOURCE_LINK=NOT_ESTABLISHED'};
  r.vulnerabilities=[html];r.riskAssessment.codeFindings=[{...fixture().riskAssessment.codeFindings[0],ruleId:html.ruleId,priority:'REVIEW_REQUIRED'}];
  r.remediation=null;
  add('html-confidence',r,['HIGH','실제 공격 성공을 입증하지 않습니다','확인할 파일'],'REVIEW_REQUIRED');
  r=base();delete r.resultSummary;add('historical',r,['새 요약 기록이 없는 이력','미기록']);
  r=base();r.comparison=require('./progress-fixture.cjs')().comparison;r.comparison.status='UNAVAILABLE';r.comparison.message='분석기 버전이 달라 비교 확인 불가';r.comparison.findings=[];
  add('version-not-compared',r,['분석기 버전이 달라 비교 확인 불가','NOT_COMPARED','RESOLVED가 아닙니다'],'PROGRESS');
  r=base();r.sourceType='GITHUB';r.sourceMetadata=require('./github-source-fixture.cjs')();add('github-contract',r,['검사 규칙 기준 참고 점수','정책 SQL 분석 미실행']);
  r=base();r.coverage.status='FAILED';Object.assign(r.resultSummary,{guidance:'ANALYSIS_INCOMPLETE',title:'완료하지 못한 검사를 확인하세요',coverageStatus:'FAILED'});add('analysis-failed',r,['완료하지 못한 검사를 확인하세요','실패']);
  return cases;
};
