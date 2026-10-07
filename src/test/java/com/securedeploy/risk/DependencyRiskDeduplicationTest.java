package com.securedeploy.risk;

import com.securedeploy.dependency.model.*;
import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.model.*;
import com.securedeploy.risk.policy.DefaultRiskPolicy;
import com.securedeploy.risk.service.RiskPrioritizationEngine;
import com.securedeploy.rule.model.*;
import com.securedeploy.sca.model.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.assertj.core.api.Assertions.*;

class DependencyRiskDeduplicationTest {
    private final RiskPrioritizationEngine engine = new RiskPrioritizationEngine(new DefaultRiskPolicy());

    @Test void repeatedAdvisoryAndAliasesAreOneFindingWithAllLocationsAndStrongestEvidence() {
        var a = advisory("OSV-1", List.of("CVE-2099-0001"), "1.0.0", "pom.xml", Severity.HIGH);
        var b = advisory("GHSA-test-1111-2222", List.of("CVE-2099-0001"), "1.0.0", "build.gradle", Severity.CRITICAL);
        var assessment = engine.assess(List.of(), sca(ScaResult.Status.COMPLETE, a, b, a));
        assertThat(assessment.dependencyFindings()).hasSize(1);
        var finding = assessment.dependencyFindings().get(0);
        assertThat(finding.advisoryId()).isEqualTo("CVE-2099-0001");
        assertThat(finding.dependency().aliases()).contains("OSV-1", "GHSA-TEST-1111-2222", "CVE-2099-0001");
        assertThat(finding.sourceFiles()).containsExactly("build.gradle", "pom.xml");
        assertThat(assessment.prioritySummary().get(RiskPriority.BLOCKING)).isEqualTo(1);
    }

    @Test void laterAliasBridgeJoinsProviderRecordsAndInputOrderDoesNotChangeCanonicalId() {
        var a = advisory("OSV-1", List.of(), "1.0.0", "pom.xml", Severity.HIGH);
        var b = advisory("GHSA-test-1111-2222", List.of(), "1.0.0", "pom.xml", Severity.HIGH);
        var bridge = advisory("CVE-2099-0001", List.of("OSV-1", "GHSA-test-1111-2222"), "1.0.0", "pom.xml", Severity.HIGH);
        var first = engine.assess(List.of(), sca(ScaResult.Status.COMPLETE, a, b, bridge));
        var reordered = engine.assess(List.of(), sca(ScaResult.Status.COMPLETE, bridge, b, a));
        assertThat(first.dependencyFindings()).hasSize(1).isEqualTo(reordered.dependencyFindings());
    }

    @Test void differentAdvisoriesAndVersionsRemainIndependent() {
        var result = engine.assess(List.of(), sca(ScaResult.Status.COMPLETE,
                advisory("CVE-2099-0001", List.of(), "1.0.0", "pom.xml", Severity.HIGH),
                advisory("CVE-2099-0002", List.of(), "1.0.0", "pom.xml", Severity.HIGH),
                advisory("CVE-2099-0001", List.of(), "2.0.0", "pom.xml", Severity.HIGH)));
        assertThat(result.dependencyFindings()).hasSize(3);
        assertThat(result.prioritySummary().get(RiskPriority.SHOULD_FIX)).isEqualTo(3);
    }

    @Test void sameAdvisoryInAnotherPackageIsNotMerged() {
        var original = advisory("CVE-2099-0001", List.of(), "1.0.0", "pom.xml", Severity.HIGH);
        var other = new DependencyVulnerability(ScaEcosystem.NPM, "fixture", "1.0.0", original.osvId(), List.of(),
                "fixture", Severity.HIGH, null, List.of(), List.of(), null, null, List.of(), List.of("package.json"));
        assertThat(engine.assess(List.of(), sca(ScaResult.Status.COMPLETE, original, other)).dependencyFindings()).hasSize(2);
    }

    @Test void idlessCatalogCandidateBecomesSupplementalContextNotAnotherRiskOrCve() {
        var result = engine.assess(List.of(candidate(1, "pom.xml", DependencyEcosystem.MAVEN, "1.0.0", null)),
                sca(ScaResult.Status.COMPLETE, advisory("CVE-2099-0001", List.of(), "1.0.0", "pom.xml", Severity.HIGH),
                        advisory("CVE-2099-0002", List.of(), "1.0.0", "pom.xml", Severity.HIGH)));
        assertThat(result.codeFindings()).isEmpty();
        assertThat(result.dependencyFindings()).hasSize(2);
        assertThat(result.dependencyCorrelations()).hasSize(1);
        var correlation = result.dependencyCorrelations().get(0);
        assertThat(correlation.relation()).isEqualTo(DependencyCorrelation.Relation.PACKAGE_CANDIDATE_CONTEXT);
        assertThat(correlation.canonicalFindingIds()).hasSize(2);
        assertThat(correlation.observation().advisoryId()).isNull();
        assertThat(result.prioritySummary().get(RiskPriority.REVIEW_REQUIRED)).isZero();
        assertThat(result.prioritySummary().get(RiskPriority.SHOULD_FIX)).isEqualTo(2);
    }

    @Test void explicitlyDifferentCatalogCveRemainsIndependent() {
        var result = engine.assess(List.of(candidate(1, "pom.xml", DependencyEcosystem.MAVEN, "1.0.0", "CVE-2099-9999")),
                sca(ScaResult.Status.COMPLETE, advisory("OSV-1", List.of("CVE-2099-0001"), "1.0.0", "pom.xml", Severity.HIGH)));
        assertThat(result.codeFindings()).hasSize(1);
        assertThat(result.dependencyCorrelations()).isEmpty();
        assertThat(result.prioritySummary().get(RiskPriority.REVIEW_REQUIRED)).isEqualTo(1);
    }

    @Test void explicitlyMatchingCatalogCveUsesAliasIdentity() {
        var result = engine.assess(List.of(candidate(1, "pom.xml", DependencyEcosystem.MAVEN, "1.0.0", "CVE-2099-0001")),
                sca(ScaResult.Status.COMPLETE, advisory("OSV-1", List.of("CVE-2099-0001"), "1.0.0", "pom.xml", Severity.HIGH)));
        assertThat(result.codeFindings()).isEmpty();
        assertThat(result.dependencyCorrelations().get(0).relation()).isEqualTo(DependencyCorrelation.Relation.SAME_ADVISORY);
    }

    @ParameterizedTest @EnumSource(value = ScaResult.Status.class, names = {"PARTIAL", "UNAVAILABLE", "DISABLED", "NO_MANIFEST"})
    void failedOrIncompleteLookupNeverAbsorbsIndependentCandidates(ScaResult.Status status) {
        var result = engine.assess(List.of(candidate(1, "pom.xml", DependencyEcosystem.MAVEN, "1.0.0", null)),
                sca(status, advisory("OSV-1", List.of(), "1.0.0", "pom.xml", Severity.HIGH)));
        assertThat(result.codeFindings()).hasSize(1);
        assertThat(result.dependencyCorrelations()).isEmpty();
    }

    @Test void versionMismatchOrRangeDoesNotCorrelateWithExactFinding() {
        for (String version : List.of("2.0.0", "[1.0,2.0)")) {
            var result = engine.assess(List.of(candidate(1, "pom.xml", DependencyEcosystem.MAVEN, version, null)),
                    sca(ScaResult.Status.COMPLETE, advisory("OSV-1", List.of(), "1.0.0", "pom.xml", Severity.HIGH)));
            assertThat(result.codeFindings()).hasSize(1);
            assertThat(result.dependencyCorrelations()).isEmpty();
        }
    }

    @Test void repeatedMavenGradleCandidateIsCountedOnceEvenWithoutOsvMatch() {
        var result = engine.assess(List.of(candidate(1, "pom.xml", DependencyEcosystem.MAVEN, "1.0.0", null),
                candidate(2, "build.gradle", DependencyEcosystem.GRADLE, "1.0.0", null)), sca(ScaResult.Status.COMPLETE));
        assertThat(result.codeFindings()).hasSize(1);
        assertThat(result.dependencyCorrelations().get(0).relation()).isEqualTo(DependencyCorrelation.Relation.REPEATED_CATALOG_OBSERVATION);
        assertThat(result.prioritySummary().get(RiskPriority.REVIEW_REQUIRED)).isEqualTo(1);
    }

    @Test void missingStructuredProvenanceIsNotGuessedFromMessageOrEvidence() {
        var finding = VulnerabilityResultResponse.from(new RuleMatch("VULNERABLE_MAVEN_DEPENDENCY", RuleCategory.DEPENDENCY,
                Severity.HIGH, "pom.xml", 1, "test.fixture:library 1.0.0", "test", "dependency=test.fixture:library, currentVersion=1.0.0"))
                .withVulnerabilityId(1L);
        var result = engine.assess(List.of(finding), sca(ScaResult.Status.COMPLETE,
                advisory("OSV-1", List.of(), "1.0.0", "pom.xml", Severity.HIGH)));
        assertThat(result.codeFindings()).hasSize(1);
        assertThat(result.dependencyCorrelations()).isEmpty();
    }

    private VulnerabilityResultResponse candidate(long id, String path, DependencyEcosystem ecosystem, String version, String advisory) {
        String rule = ecosystem == DependencyEcosystem.GRADLE ? "VULNERABLE_GRADLE_DEPENDENCY" : "VULNERABLE_MAVEN_DEPENDENCY";
        return VulnerabilityResultResponse.from(new RuleMatch(rule, RuleCategory.DEPENDENCY, Severity.HIGH,
                path, 3, "Candidate", "test", "masked", FalsePositiveRisk.LOW, DetectionConfidence.HIGH, "Pattern match")
                .withDependencyObservation(new DependencyObservation("BUILTIN_CATALOG", ecosystem, "test.fixture:library", version, advisory)))
                .withVulnerabilityId(id);
    }
    private DependencyVulnerability advisory(String id, List<String> aliases, String version, String path, Severity severity) {
        return new DependencyVulnerability(ScaEcosystem.MAVEN, "test.fixture:library", version, id, aliases,
                "Synthetic advisory", severity, null, List.of(), List.of(), null, null, List.of(), List.of(path));
    }
    private ScaResult sca(ScaResult.Status status, DependencyVulnerability... findings) {
        var components = Arrays.stream(findings).map(f -> new DependencyComponent(f.ecosystem(), f.packageName(),
                f.installedVersion(), "runtime", true, f.sourceFiles().get(0), 0, VersionResolution.EXACT)).distinct().toList();
        int count = (int) components.stream().map(DependencyComponent::identity).distinct().count();
        return new ScaResult(1, status, Instant.now(), new ScaResult.Summary(count, count, 0, count, findings.length, Map.of()),
                components, List.of(findings), List.of());
    }
}
