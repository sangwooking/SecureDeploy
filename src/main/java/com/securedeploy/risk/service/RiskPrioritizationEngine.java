package com.securedeploy.risk.service;

import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.model.*;
import com.securedeploy.risk.model.RiskAssessment.Completion;
import com.securedeploy.risk.model.RiskFinding.DependencyFacts;
import com.securedeploy.risk.model.RiskFinding.Source;
import com.securedeploy.risk.policy.RiskPolicy;
import com.securedeploy.risk.policy.RiskReason;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.sca.model.*;
import com.securedeploy.threatintel.model.*;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;

@Service
public class RiskPrioritizationEngine {
    private final RiskPolicy policy;

    public RiskPrioritizationEngine(RiskPolicy policy) { this.policy = policy; }

    // Called only for a newly completed Rule Engine run, never to reinterpret history on read.
    public RiskAssessment assess(List<VulnerabilityResultResponse> code, ScaResult sca) {
        return assess(code, sca, null);
    }

    public RiskAssessment assess(List<VulnerabilityResultResponse> code, ScaResult sca, ThreatIntelligenceSnapshot intelligence) {
        List<RiskFinding> codeFindings = new ArrayList<>();
        for (int i = 0; i < code.size(); i++) {
            var finding = code.get(i);
            var decision = policy.code(finding);
            codeFindings.add(new RiskFinding("code:" + (finding.vulnerabilityId() == null ? "index:" + i : finding.vulnerabilityId()),
                    Source.CODE, category(finding.category()), finding.vulnerabilityId(), finding.ruleId(),
                    null, null, null, null, List.of(finding.filePath()), decision.priority(),
                    decision.reason().name(), decision.reason().message(), null));
        }

        List<RiskFinding> dependencies = new ArrayList<>();
        List<RiskFinding> requirements = new ArrayList<>();
        boolean scaComplete = complete(sca);
        Set<String> threatReviewFiles = new TreeSet<>();
        boolean threatReviewRequired = false;
        if (sca != null) {
            for (DependencyVulnerability finding : new DependencyFindingCanonicalizer().canonicalize(sca.dependencyVulnerabilities())) {
                List<DependencyComponent> components = sca.components().stream().filter(c ->
                        c.ecosystem() == finding.ecosystem() && Objects.equals(c.packageName(), finding.packageName())
                                && Objects.equals(c.version(), finding.installedVersion())).toList();
                boolean exact = !components.isEmpty() && components.stream().allMatch(c -> c.versionResolution() == VersionResolution.EXACT);
                Boolean direct = components.stream().anyMatch(c -> Boolean.TRUE.equals(c.direct())) ? Boolean.TRUE
                        : !components.isEmpty() && components.stream().allMatch(c -> Boolean.FALSE.equals(c.direct())) ? Boolean.FALSE : null;
                DependencyFacts facts = new DependencyFacts(exact, scaComplete && exact, direct,
                        components.stream().map(DependencyComponent::scope).filter(Objects::nonNull).distinct().sorted().toList(),
                        !finding.fixedVersions().isEmpty(), finding.cvssScore());
                List<ThreatIntelligence> signals = intelligence == null ? List.of() : CveIdentifiers.from(finding).stream()
                        .map(intelligence.cves()::get).filter(Objects::nonNull).toList();
                var decision = policy.dependency(finding, facts, signals);
                if (policy.requiresThreatReview(finding, facts, signals)) {
                    threatReviewRequired = true;
                    threatReviewFiles.addAll(finding.sourceFiles());
                }
                dependencies.add(new RiskFinding(DependencyFindingCanonicalizer.identity(finding), Source.DEPENDENCY,
                        FindingCategory.DEPENDENCY, null, null, finding.ecosystem().name(), finding.packageName(),
                        finding.installedVersion(), finding.osvId(), finding.sourceFiles(), decision.priority(),
                        decision.reason().name(), decision.reason().message(), facts, finding));
            }
            Map<String, List<DependencyComponent>> unresolved = new LinkedHashMap<>();
            sca.components().stream().filter(c -> c.versionResolution() != VersionResolution.EXACT)
                    .forEach(c -> unresolved.computeIfAbsent(c.identity(), key -> new ArrayList<>()).add(c));
            unresolved.forEach((key, components) -> {
                var c = components.get(0);
                requirements.add(new RiskFinding("unresolved:" + key, Source.DEPENDENCY, FindingCategory.DEPENDENCY,
                        null, null, c.ecosystem().name(), c.packageName(), c.version(), null,
                        components.stream().map(DependencyComponent::sourceFile).distinct().sorted().toList(),
                        RiskPriority.REVIEW_REQUIRED, RiskReason.UNRESOLVED_VERSION.name(), RiskReason.UNRESOLVED_VERSION.message(), null));
            });
        }
        if (!scaComplete) {
            requirements.add(new RiskFinding("coverage:sca", Source.ANALYSIS, FindingCategory.ANALYSIS,
                    null, null, null, null, null, null, List.of(), RiskPriority.REVIEW_REQUIRED,
                    RiskReason.INCOMPLETE_SCA.name(), RiskReason.INCOMPLETE_SCA.message(), null));
        }

        if (threatReviewRequired) requirements.add(new RiskFinding("coverage:threat-intelligence", Source.ANALYSIS,
                FindingCategory.ANALYSIS, null, null, null, null, null, null, List.copyOf(threatReviewFiles),
                RiskPriority.REVIEW_REQUIRED, RiskReason.INCOMPLETE_THREAT_INTELLIGENCE.name(),
                RiskReason.INCOMPLETE_THREAT_INTELLIGENCE.message(), null));

        var correlated = new DependencyFindingCorrelator().correlate(code, codeFindings, dependencies, scaComplete);
        codeFindings = new ArrayList<>(correlated.codeFindings());
        List<RiskFinding> all = new ArrayList<>(codeFindings);
        all.addAll(dependencies);
        all.addAll(requirements);
        Map<RiskPriority, Long> summary = counts(all);
        Map<Source, Map<RiskPriority, Long>> bySource = new EnumMap<>(Source.class);
        for (Source source : Source.values()) bySource.put(source, counts(all.stream().filter(f -> f.source() == source).toList()));
        DeploymentAssessment assessment = summary.get(RiskPriority.BLOCKING) > 0 ? DeploymentAssessment.BLOCKED
                : summary.get(RiskPriority.REVIEW_REQUIRED) > 0 ? DeploymentAssessment.REVIEW_REQUIRED
                : summary.get(RiskPriority.SHOULD_FIX) > 0 ? DeploymentAssessment.READY_WITH_WARNINGS : DeploymentAssessment.READY;
        Completion scaCompletion = scaComplete ? Completion.COMPLETE : sca == null ? Completion.UNKNOWN
                : sca.status() == ScaResult.Status.UNAVAILABLE ? Completion.FAILED
                : sca.status() == ScaResult.Status.DISABLED ? Completion.NOT_INCLUDED : Completion.PARTIAL;
        boolean hasCves = sca != null && sca.dependencyVulnerabilities().stream().anyMatch(f -> !CveIdentifiers.from(f).isEmpty());
        var threatStatus = intelligence != null ? intelligence.status() : hasCves ? ThreatIntelligenceSnapshot.Status.UNKNOWN
                : ThreatIntelligenceSnapshot.Status.NOT_APPLICABLE;
        boolean threatComplete = threatStatus == ThreatIntelligenceSnapshot.Status.COMPLETE || threatStatus == ThreatIntelligenceSnapshot.Status.NOT_APPLICABLE;
        return new RiskAssessment(3, policy.version(), Instant.now(), "RULE_ENGINE_SCA_AND_THREAT_INTELLIGENCE", assessment,
                assessmentReason(assessment, summary), new RiskAssessment.Coverage(
                        scaComplete && threatComplete ? Completion.COMPLETE : Completion.PARTIAL, Completion.COMPLETE,
                        scaCompletion, Completion.NOT_INCLUDED,
                        "지원 파일·정적 룰·정확한 의존성 버전과 분석 당시 악용 정보 범위의 판단입니다. 전체 코드, 실제 설치, 도달 가능성, 외부 노출, AI 진단은 포함하지 않습니다. READY도 절대적 안전을 보장하지 않습니다.", threatStatus),
                summary, bySource, List.copyOf(codeFindings), List.copyOf(dependencies), List.copyOf(requirements), correlated.correlations(), intelligence, policy.threatThresholds());
    }

    private boolean complete(ScaResult sca) {
        if (sca == null || sca.status() != ScaResult.Status.COMPLETE || !sca.warnings().isEmpty()) return false;
        if (sca.components().stream().anyMatch(c -> c.versionResolution() != VersionResolution.EXACT)) return false;
        long identities = sca.components().stream().map(DependencyComponent::identity).distinct().count();
        return sca.summary().unresolvedDependencies() == 0 && sca.summary().dependenciesAnalyzed() == identities
                && sca.summary().dependenciesDiscovered() == identities;
    }

    private Map<RiskPriority, Long> counts(List<RiskFinding> findings) {
        Map<RiskPriority, Long> counts = new EnumMap<>(RiskPriority.class);
        for (RiskPriority priority : RiskPriority.values()) counts.put(priority, 0L);
        findings.forEach(f -> counts.merge(f.priority(), 1L, Long::sum));
        return counts;
    }

    private String assessmentReason(DeploymentAssessment assessment, Map<RiskPriority, Long> counts) {
        return switch (assessment) {
            case BLOCKED -> "배포 전에 해결해야 할 차단 항목이 " + counts.get(RiskPriority.BLOCKING) + "건 있습니다. 별도 검토 필요 항목도 확인하세요.";
            case REVIEW_REQUIRED -> "자동 판단에 필요한 정보가 부족한 항목이 " + counts.get(RiskPriority.REVIEW_REQUIRED) + "건 있습니다. 확인 전에는 배포 가능으로 판단하지 않습니다.";
            case READY_WITH_WARNINGS -> "필수 분석 범위의 조회가 완료되었으며 수정 권장 항목이 " + counts.get(RiskPriority.SHOULD_FIX) + "건 남아 있습니다.";
            case READY -> "완료된 정적 분석 범위에서 차단 또는 추가 검토 항목이 없습니다. 배포 환경의 절대적 안전을 보장하지는 않습니다.";
        };
    }

    private FindingCategory category(RuleCategory category) {
        if (category == null) return FindingCategory.CODE;
        return switch (category) {
            case SECRET_MANAGEMENT, CLIENT_SECRET_EXPOSURE -> FindingCategory.SECRET;
            case DEPENDENCY -> FindingCategory.DEPENDENCY;
            case CONFIGURATION, DEVOPS_SECURITY -> FindingCategory.CONFIG;
            case CONTAINER_SECURITY -> FindingCategory.CONTAINER;
            case KUBERNETES_SECURITY -> FindingCategory.IAC;
            case CI_CD_SECURITY -> FindingCategory.CI_CD;
            default -> FindingCategory.CODE;
        };
    }
}
