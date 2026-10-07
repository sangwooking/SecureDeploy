package com.securedeploy.risk;

import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.model.*;
import com.securedeploy.risk.model.RiskFinding.DependencyFacts;
import com.securedeploy.risk.persistence.RiskAssessmentConverter;
import com.securedeploy.risk.policy.DefaultRiskPolicy;
import com.securedeploy.risk.service.RiskPrioritizationEngine;
import com.securedeploy.rule.model.*;
import com.securedeploy.sca.model.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;
import static com.securedeploy.risk.model.RiskPriority.*;
import static com.securedeploy.risk.model.DeploymentAssessment.BLOCKED;
import static com.securedeploy.risk.model.DeploymentAssessment.READY;
import static com.securedeploy.risk.model.DeploymentAssessment.READY_WITH_WARNINGS;

class RiskPrioritizationEngineTest {
    private final DefaultRiskPolicy policy = new DefaultRiskPolicy();
    private final RiskPrioritizationEngine engine = new RiskPrioritizationEngine(policy);

    @Test void highConfidenceCredentialBlocksWithoutChangingSeverity() {
        var finding = code("HARDCODED_SECRET", Severity.HIGH, DetectionConfidence.HIGH, FalsePositiveRisk.LOW, "Fake test evidence evaluated");
        var result = engine.assess(List.of(finding), emptySca());
        assertThat(result.codeFindings().get(0).priority()).isEqualTo(BLOCKING);
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(BLOCKED);
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
    }
    @ParameterizedTest @EnumSource(Severity.class)
    void lowConfidenceIsNeverAutomaticallySafeOrBlocking(Severity severity) {
        var result = engine.assess(List.of(code("HARDCODED_SECRET", severity, DetectionConfidence.LOW,
                FalsePositiveRisk.HIGH, "Placeholder fixture")), emptySca());
        assertThat(result.codeFindings().get(0).priority()).isEqualTo(REVIEW_REQUIRED);
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(DeploymentAssessment.REVIEW_REQUIRED);
    }
    @ParameterizedTest @ValueSource(strings = {"DANGEROUS_SQL", "PERMIT_ALL_USAGE", "REACT_DANGEROUS_HTML", "EXPOSED_ACTUATOR", "CORS_WILDCARD", "VULNERABLE_MAVEN_DEPENDENCY"})
    void patternOnlyFindingsRequireContextEvenWithDefaultHighConfidence(String ruleId) {
        assertThat(policy.code(code(ruleId, Severity.HIGH, DetectionConfidence.HIGH, FalsePositiveRisk.LOW, "Pattern match")).priority())
                .isEqualTo(REVIEW_REQUIRED);
    }
    @Test void highSeverityAloneDoesNotBlockNewOrUncalibratedRules() {
        assertThat(policy.code(code("FUTURE_RULE", Severity.CRITICAL, DetectionConfidence.HIGH, FalsePositiveRisk.LOW, "Pattern match")).priority())
                .isEqualTo(SHOULD_FIX);
    }
    @Test void missingMetadataDoesNotInventHighConfidence() {
        assertThat(policy.code(code("HARDCODED_SECRET", Severity.HIGH, null, null, null)).priority()).isEqualTo(REVIEW_REQUIRED);
        assertThat(policy.code(code("HARDCODED_SECRET", Severity.HIGH, DetectionConfidence.HIGH, FalsePositiveRisk.LOW, " ")).priority()).isEqualTo(REVIEW_REQUIRED);
    }
    @Test void mediumConfidenceHighSeverityRequiresReview() {
        assertThat(policy.code(code("HARDCODED_SECRET", Severity.HIGH, DetectionConfidence.MEDIUM, FalsePositiveRisk.LOW, "note")).priority()).isEqualTo(REVIEW_REQUIRED);
        assertThat(policy.code(code("HARDCODED_SECRET", Severity.HIGH, DetectionConfidence.HIGH, FalsePositiveRisk.MEDIUM, "note")).priority()).isEqualTo(REVIEW_REQUIRED);
    }
    @Test void explicitRulePolicyCanPromoteMediumWithoutRewritingSeverity() {
        var finding = code("GITHUB_ACTIONS_SECRET_ECHO", Severity.MEDIUM, DetectionConfidence.HIGH, FalsePositiveRisk.LOW, "secret output");
        assertThat(policy.code(finding).priority()).isEqualTo(BLOCKING);
        assertThat(finding.severity()).isEqualTo(Severity.MEDIUM);
    }
    @Test void weakJwtPatternIsFixRecommendedNotProvenAuthBypass() {
        assertThat(policy.code(code("WEAK_JWT_SECRET", Severity.HIGH, DetectionConfidence.HIGH, FalsePositiveRisk.LOW, "length match")).priority()).isEqualTo(SHOULD_FIX);
    }
    @Test void exactCriticalOsvFindingBlocksIncludingTransitiveWithoutFix() {
        var sca = sca(ScaResult.Status.COMPLETE, List.of(component("1.0.0", VersionResolution.EXACT, false)), List.of(dependency(Severity.CRITICAL, null)), 1);
        var result = engine.assess(List.of(), sca);
        var finding = result.dependencyFindings().get(0);
        assertThat(finding.priority()).isEqualTo(BLOCKING);
        assertThat(finding.dependencyFacts().direct()).isFalse();
        assertThat(finding.dependencyFacts().fixedVersionAvailable()).isFalse();
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(BLOCKED);
    }
    @ParameterizedTest @EnumSource(Severity.class)
    void dependencySeverityPolicy(Severity severity) {
        RiskPriority expected = switch (severity) {
            case CRITICAL -> BLOCKING;
            case HIGH, MEDIUM -> SHOULD_FIX;
            case LOW -> INFORMATIONAL;
        };
        assertThat(policy.dependency(dependency(severity, null), facts(true, true)).priority()).isEqualTo(expected);
    }
    @Test void validNumericCvssCanEscalateButCannotLowerKnownSeverity() {
        assertThat(policy.dependency(dependency(null, 9.8), facts(true, true)).priority()).isEqualTo(BLOCKING);
        assertThat(policy.dependency(dependency(Severity.HIGH, 9.8), facts(true, true)).priority()).isEqualTo(BLOCKING);
        assertThat(policy.dependency(dependency(Severity.CRITICAL, 2.0), facts(true, true)).priority()).isEqualTo(BLOCKING);
        assertThat(policy.dependency(dependency(null, 11.0), facts(true, true)).priority()).isEqualTo(REVIEW_REQUIRED);
        assertThat(policy.dependency(dependency(null, Double.NaN), facts(true, true)).priority()).isEqualTo(REVIEW_REQUIRED);
    }
    @Test void missingSeverityOrLookupNeverBecomesLow() {
        assertThat(policy.dependency(dependency(null, null), facts(true, true)).priority()).isEqualTo(REVIEW_REQUIRED);
        assertThat(policy.dependency(dependency(Severity.CRITICAL, 10.0), facts(false, true)).priority()).isEqualTo(REVIEW_REQUIRED);
        assertThat(policy.dependency(dependency(Severity.CRITICAL, 10.0), facts(true, false)).priority()).isEqualTo(REVIEW_REQUIRED);
    }
    @Test void unresolvedVersionsProduceDeduplicatedLocatedReviewItems() {
        var c = component("^1.0.0", VersionResolution.RANGE, true);
        var result = engine.assess(List.of(), sca(ScaResult.Status.PARTIAL, List.of(c, c), List.of(), 0));
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(DeploymentAssessment.REVIEW_REQUIRED);
        assertThat(result.reviewRequirements()).hasSize(2);
        assertThat(result.reviewRequirements().get(0).sourceFiles()).containsExactly("package.json");
    }
    @ParameterizedTest @EnumSource(value = ScaResult.Status.class, names = {"PARTIAL", "UNAVAILABLE", "DISABLED", "NO_MANIFEST"})
    void everyIncompleteStateRequiresReviewEvenWithZeroFindings(ScaResult.Status status) {
        var result = engine.assess(List.of(), sca(status, List.of(), List.of(), 0));
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(DeploymentAssessment.REVIEW_REQUIRED);
        assertThat(result.assessmentCoverage().overall()).isEqualTo(RiskAssessment.Completion.PARTIAL);
        if (status == ScaResult.Status.UNAVAILABLE) assertThat(result.assessmentCoverage().sca()).isEqualTo(RiskAssessment.Completion.FAILED);
    }
    @Test void missingScaIsNotSafe() {
        assertThat(engine.assess(List.of(), null).prioritizedDeploymentAssessment()).isEqualTo(DeploymentAssessment.REVIEW_REQUIRED);
    }
    @Test void partialLookupCannotClaimPerPackageConfirmation() {
        var result = engine.assess(List.of(), sca(ScaResult.Status.PARTIAL,
                List.of(component("1.0.0", VersionResolution.EXACT, true)), List.of(dependency(Severity.CRITICAL, null)), 1));
        assertThat(result.dependencyFindings().get(0).priority()).isEqualTo(REVIEW_REQUIRED);
        assertThat(result.dependencyFindings().get(0).dependencyFacts().lookupConfirmed()).isFalse();
    }
    @Test void inconsistentCompleteSummaryIsNotSafe() {
        var result = engine.assess(List.of(), sca(ScaResult.Status.COMPLETE,
                List.of(component("1.0.0", VersionResolution.EXACT, true)), List.of(), 0));
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(DeploymentAssessment.REVIEW_REQUIRED);
    }
    @Test void unmatchedFindingCannotBlockAsAnExactVersion() {
        var result = engine.assess(List.of(), sca(ScaResult.Status.COMPLETE, List.of(), List.of(dependency(Severity.CRITICAL, null)), 0));
        assertThat(result.dependencyFindings().get(0).priority()).isEqualTo(REVIEW_REQUIRED);
        assertThat(result.dependencyFindings().get(0).dependencyFacts().direct()).isNull();
    }
    @Test void deploymentPrecedenceAndSummaryIncludeBothFindingsAndCoverage() {
        var result = engine.assess(List.of(code("HARDCODED_SECRET", Severity.HIGH, DetectionConfidence.HIGH,
                FalsePositiveRisk.LOW, "note")), null);
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(BLOCKED);
        assertThat(result.prioritySummary()).containsEntry(BLOCKING, 1L).containsEntry(REVIEW_REQUIRED, 1L);
        assertThat(result.prioritySummaryBySource().get(RiskFinding.Source.ANALYSIS)).containsEntry(REVIEW_REQUIRED, 1L);
    }
    @Test void shouldFixOnlyProducesReadyWithWarnings() {
        var result = engine.assess(List.of(code("DEBUG_ENABLED", Severity.MEDIUM, DetectionConfidence.HIGH,
                FalsePositiveRisk.LOW, "note")), emptySca());
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(READY_WITH_WARNINGS);
    }
    @Test void completedEmptyOrInformationalAnalysisProducesScopedReady() {
        assertThat(engine.assess(List.of(), emptySca()).prioritizedDeploymentAssessment()).isEqualTo(READY);
        var result = engine.assess(List.of(code("NGINX_SERVER_TOKENS", Severity.LOW, DetectionConfidence.HIGH,
                FalsePositiveRisk.LOW, "note")), emptySca());
        assertThat(result.prioritizedDeploymentAssessment()).isEqualTo(READY);
        assertThat(result.assessmentCoverage().ai()).isEqualTo(RiskAssessment.Completion.NOT_INCLUDED);
        assertThat(result.assessmentCoverage().scopeNote()).contains("절대적 안전");
    }
    @Test void snapshotRoundTripPreservesPolicyReasonsAndCountsWithoutRecalculation() {
        var result = engine.assess(List.of(code("HARDCODED_SECRET", Severity.HIGH, DetectionConfidence.HIGH,
                FalsePositiveRisk.LOW, "note")), emptySca());
        var converter = new RiskAssessmentConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(result))).isEqualTo(result);
        assertThat(converter.convertToEntityAttribute(null)).isNull();
    }

    private VulnerabilityResultResponse code(String id, Severity severity, DetectionConfidence confidence, FalsePositiveRisk risk, String note) {
        return VulnerabilityResultResponse.from(new RuleMatch(id, RuleCategory.SECRET_MANAGEMENT, severity,
                "application.yml", 1, "Test finding", "Test recommendation", "<redacted>", risk, confidence, note));
    }
    private DependencyFacts facts(boolean exact, boolean lookup) { return new DependencyFacts(exact, lookup, null, List.of(), false, null); }
    private DependencyComponent component(String version, VersionResolution resolution, Boolean direct) {
        return new DependencyComponent(ScaEcosystem.NPM, "fixture", version, "dependencies", direct, "package.json", 0, resolution);
    }
    private DependencyVulnerability dependency(Severity severity, Double cvss) {
        return new DependencyVulnerability(ScaEcosystem.NPM, "fixture", "1.0.0", "TEST-1", List.of(), "Test advisory",
                severity, cvss, List.of(), List.of(), null, null, List.of(), List.of("package.json"));
    }
    private ScaResult emptySca() { return sca(ScaResult.Status.COMPLETE, List.of(), List.of(), 0); }
    private ScaResult sca(ScaResult.Status status, List<DependencyComponent> components, List<DependencyVulnerability> findings, int analyzed) {
        int distinct = (int) components.stream().map(DependencyComponent::identity).distinct().count();
        int unresolved = (int) components.stream().filter(c -> c.versionResolution() != VersionResolution.EXACT).map(DependencyComponent::identity).distinct().count();
        return new ScaResult(1, status, Instant.now(), new ScaResult.Summary(distinct, analyzed, unresolved, findings.isEmpty() ? 0 : 1, findings.size(), Map.of()),
                components, findings, List.of());
    }
}
