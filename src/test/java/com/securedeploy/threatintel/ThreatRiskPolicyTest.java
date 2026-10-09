package com.securedeploy.threatintel;

import com.securedeploy.risk.model.*;
import com.securedeploy.risk.policy.*;
import com.securedeploy.risk.service.RiskPrioritizationEngine;
import com.securedeploy.risk.persistence.RiskAssessmentConverter;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.sca.model.*;
import com.securedeploy.threatintel.model.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static com.securedeploy.threatintel.ThreatFixtures.*;
import static com.securedeploy.risk.model.RiskPriority.*;
import static org.assertj.core.api.Assertions.*;

class ThreatRiskPolicyTest {
    DefaultRiskPolicy policy = new DefaultRiskPolicy();
    RiskFinding.DependencyFacts facts = new RiskFinding.DependencyFacts(true, true, true, List.of("runtime"), true, null);
    DependencyVulnerability finding(Severity severity) {
        return new DependencyVulnerability(ScaEcosystem.NPM, "fixture", "1.0.0", "GHSA-fixture", List.of(CVE),
                "Synthetic", severity, null, List.of(), List.of(), null, null, List.of(), List.of("package.json"));
    }
    List<ThreatIntelligence> intel(double score, double percentile, Boolean known, LookupStatus kevStatus) {
        return List.of(new ThreatIntelligence(CVE, epss(score, percentile), kev(known, kevStatus)));
    }
    @ParameterizedTest @EnumSource(Severity.class)
    void kevBlocksEveryConfirmedAffectedSeverityWithDistinctReason(Severity severity) {
        var decision = policy.dependency(finding(severity), facts, intel(.01, .1, true, LookupStatus.AVAILABLE));
        assertThat(decision.priority()).isEqualTo(BLOCKING);
        assertThat(decision.reason()).isEqualTo(RiskReason.KNOWN_EXPLOITED_VULNERABILITY);
    }
    @Test void uncertaintyAboutAffectedVersionPreventsKevBlocking() {
        for (var uncertain : List.of(new RiskFinding.DependencyFacts(false, true, null, List.of(), false, null),
                new RiskFinding.DependencyFacts(true, false, null, List.of(), false, null))) {
            assertThat(policy.dependency(finding(Severity.HIGH), uncertain, intel(.9, .99, true, LookupStatus.AVAILABLE)).priority()).isEqualTo(REVIEW_REQUIRED);
        }
    }
    @Test void epssRequiresHighSeverityBothThresholdsAndFreshData() {
        var decision = policy.dependency(finding(Severity.HIGH), facts, intel(.5, .95, false, LookupStatus.AVAILABLE));
        assertThat(decision.priority()).isEqualTo(BLOCKING);
        assertThat(decision.reason()).isEqualTo(RiskReason.HIGH_EXPLOIT_PROBABILITY);
        assertThat(policy.dependency(finding(Severity.HIGH), facts, intel(.49, .99, false, LookupStatus.AVAILABLE)).priority()).isEqualTo(SHOULD_FIX);
        assertThat(policy.dependency(finding(Severity.HIGH), facts, intel(.99, .94, false, LookupStatus.AVAILABLE)).priority()).isEqualTo(SHOULD_FIX);
        assertThat(policy.dependency(finding(Severity.MEDIUM), facts, intel(.99, .99, false, LookupStatus.AVAILABLE)).priority()).isEqualTo(SHOULD_FIX);
        assertThat(policy.dependency(finding(Severity.LOW), facts, intel(.99, .99, false, LookupStatus.AVAILABLE)).priority()).isEqualTo(INFORMATIONAL);
    }
    @ParameterizedTest @EnumSource(Severity.class)
    void lowEpssNeverDowngradesBaseline(Severity severity) {
        assertThat(policy.dependency(finding(severity), facts, intel(0, 0, false, LookupStatus.AVAILABLE)).priority())
                .isEqualTo(policy.dependency(finding(severity), facts).priority());
    }
    @Test void thresholdsAreConfigurableAndValidated() {
        var custom = new DefaultRiskPolicy(new ThreatRiskThresholds(.8, .99));
        assertThat(custom.dependency(finding(Severity.HIGH), facts, intel(.7, .98, false, LookupStatus.AVAILABLE)).priority()).isEqualTo(SHOULD_FIX);
        assertThatThrownBy(() -> new ThreatRiskThresholds(Double.NaN, .95)).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void staleKevPositiveStillBlocksAndOverridesEpssReason() {
        var decision = policy.dependency(finding(Severity.HIGH), facts, intel(.99, .99, true, LookupStatus.STALE));
        assertThat(decision.reason()).isEqualTo(RiskReason.KNOWN_EXPLOITED_VULNERABILITY);
    }
    @Test void failureOrStaleEpssRetainsBasePriorityAndRequiresReviewForHigh() {
        for (LookupStatus status : List.of(LookupStatus.UNAVAILABLE, LookupStatus.NOT_FOUND, LookupStatus.STALE)) {
            var data = List.of(new ThreatIntelligence(CVE, epss(.99, .99).withStatus(status), kev(false, LookupStatus.AVAILABLE)));
            assertThat(policy.dependency(finding(Severity.HIGH), facts, data).priority()).isEqualTo(SHOULD_FIX);
            assertThat(policy.requiresThreatReview(finding(Severity.HIGH), facts, data)).isTrue();
        }
    }
    @Test void kevFailureCannotTurnLowIntoScopedReadyAndDoesNotEraseCriticalBlock() {
        var data = intel(.001, .1, null, LookupStatus.UNAVAILABLE);
        assertThat(policy.requiresThreatReview(finding(Severity.LOW), facts, data)).isTrue();
        assertThat(policy.dependency(finding(Severity.CRITICAL), facts, data).priority()).isEqualTo(BLOCKING);
    }
    @Test void unknownOrUnrelatedCveNeverProvidesEscalationEvidence() {
        var unrelated = new DependencyVulnerability(ScaEcosystem.NPM, "fixture", "1.0.0", "OSV-no-cve", List.of(),
                "fixture", Severity.HIGH, null, List.of(), List.of(), null, null, List.of(), List.of("package.json"));
        assertThat(policy.dependency(unrelated, facts, intel(.99, .99, true, LookupStatus.AVAILABLE)).priority()).isEqualTo(SHOULD_FIX);
        assertThat(policy.requiresThreatReview(unrelated, facts, List.of())).isFalse();
    }
    @Test void snapshotRoundTripIncludesInputsThresholdsAndSeparateCoverage() throws Exception {
        var dep = finding(Severity.HIGH);
        var component = new DependencyComponent(ScaEcosystem.NPM, "fixture", "1.0.0", "runtime", true, "package.json", 1, VersionResolution.EXACT);
        var sca = new ScaResult(1, ScaResult.Status.COMPLETE, NOW, new ScaResult.Summary(1,1,0,1,1,Map.of()), List.of(component), List.of(dep), List.of());
        var intelligence = new ThreatIntelligenceSnapshot("test-snapshot", NOW, ThreatIntelligenceSnapshot.Status.UNAVAILABLE,
                1, 0, Map.of(), List.of("Offline fixture"));
        var assessment = new RiskPrioritizationEngine(policy).assess(List.of(), sca, intelligence);
        assertThat(assessment.dependencyFindings().get(0).priority()).isEqualTo(SHOULD_FIX);
        assertThat(assessment.prioritizedDeploymentAssessment()).isEqualTo(DeploymentAssessment.REVIEW_REQUIRED);
        assertThat(assessment.assessmentCoverage().sca()).isEqualTo(RiskAssessment.Completion.COMPLETE);
        assertThat(assessment.assessmentCoverage().threatIntelligence()).isEqualTo(ThreatIntelligenceSnapshot.Status.UNAVAILABLE);
        var converter = new RiskAssessmentConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(assessment))).isEqualTo(assessment);
        var tree = new com.fasterxml.jackson.databind.ObjectMapper().readTree(converter.convertToDatabaseColumn(assessment));
        ((com.fasterxml.jackson.databind.node.ObjectNode) tree).remove(List.of("threatIntelligence", "threatPolicy"));
        ((com.fasterxml.jackson.databind.node.ObjectNode) tree.get("assessmentCoverage")).remove("threatIntelligence");
        ((com.fasterxml.jackson.databind.node.ObjectNode) tree).put("schemaVersion", 2).put("policyVersion", "risk-v1.1");
        var legacy = converter.convertToEntityAttribute(tree.toString());
        assertThat(legacy.threatIntelligence()).isNull();
        assertThat(legacy.policyVersion()).isEqualTo("risk-v1.1");
    }
}
