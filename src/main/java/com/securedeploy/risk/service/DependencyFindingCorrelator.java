package com.securedeploy.risk.service;

import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.model.DependencyCorrelation;
import com.securedeploy.risk.model.RiskFinding;
import com.securedeploy.sca.model.ScaEcosystem;
import com.securedeploy.sca.model.VersionResolution;
import com.securedeploy.sca.parser.VersionClassifier;
import java.util.*;

public final class DependencyFindingCorrelator {
    private static final Set<String> CATALOG_RULES = Set.of("VULNERABLE_NPM_DEPENDENCY", "VULNERABLE_MAVEN_DEPENDENCY", "VULNERABLE_GRADLE_DEPENDENCY");
    public record Result(List<RiskFinding> codeFindings, List<DependencyCorrelation> correlations) { }
    private record ObservationKey(String source, ScaEcosystem ecosystem, String name, String version, String advisory) { }

    public Result correlate(List<VulnerabilityResultResponse> originals, List<RiskFinding> code,
                            List<RiskFinding> dependencies, boolean lookupComplete) {
        List<RiskFinding> retained = new ArrayList<>();
        List<DependencyCorrelation> correlations = new ArrayList<>();
        Map<ObservationKey, String> candidates = new HashMap<>();
        for (int index = 0; index < originals.size(); index++) {
            var original = originals.get(index);
            var finding = code.get(index);
            var observation = original.dependencyObservation();
            if (observation == null || !CATALOG_RULES.contains(original.ruleId())) { retained.add(finding); continue; }
            ScaEcosystem ecosystem = switch (observation.ecosystem()) {
                case NPM -> ScaEcosystem.NPM;
                case MAVEN, GRADLE -> ScaEcosystem.MAVEN;
                case DOCKER -> null;
            };
            if (ecosystem == null || VersionClassifier.classify(ecosystem, observation.version()) != VersionResolution.EXACT) {
                retained.add(finding); continue;
            }
            String advisory = observation.advisoryId() == null || observation.advisoryId().isBlank()
                    ? null : DependencyFindingCanonicalizer.normalizeId(observation.advisoryId());
            var matches = dependencies.stream().filter(f -> lookupComplete && f.dependencyFacts().lookupConfirmed()
                    && f.ecosystem().equals(ecosystem.name()) && f.packageName().equals(observation.packageName())
                    && f.version().equals(observation.version())
                    && (advisory == null || f.dependency().aliases().contains(advisory))).toList();
            if (!matches.isEmpty()) {
                correlations.add(new DependencyCorrelation(original.vulnerabilityId(), original.ruleId(), original.filePath(), original.line(),
                        observation, advisory == null ? DependencyCorrelation.Relation.PACKAGE_CANDIDATE_CONTEXT : DependencyCorrelation.Relation.SAME_ADVISORY,
                        matches.stream().map(RiskFinding::findingId).toList(), advisory == null
                        ? "내장 버전 후보를 같은 정확한 패키지/버전의 OSV 결과에 보조 근거로 연결했습니다. 개별 CVE와 동일하다고 확정한 것은 아니며 Priority에 별도 합산하지 않습니다."
                        : "동일 패키지/버전 및 advisory ID가 일치하여 하나의 위험 항목으로 집계했습니다."));
                continue;
            }
            var key = new ObservationKey(observation.source(), ecosystem, observation.packageName(), observation.version(), advisory);
            String primary = candidates.putIfAbsent(key, finding.findingId());
            if (primary == null) retained.add(finding);
            else correlations.add(new DependencyCorrelation(original.vulnerabilityId(), original.ruleId(), original.filePath(), original.line(),
                    observation, DependencyCorrelation.Relation.REPEATED_CATALOG_OBSERVATION, List.of(primary),
                    "같은 내장 catalog의 패키지/버전 후보가 여러 파일에서 반복되어 한 번만 집계했습니다. 원본 위치는 보존됩니다."));
        }
        return new Result(List.copyOf(retained), List.copyOf(correlations));
    }
}
