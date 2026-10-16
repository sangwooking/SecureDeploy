package com.securedeploy.project.progress;

import com.securedeploy.persistence.entity.*;
import com.securedeploy.review.model.*;
import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.service.RiskPrioritizationEngine;
import com.securedeploy.risk.policy.DefaultRiskPolicy;
import com.securedeploy.rule.model.*;
import com.securedeploy.sca.model.*;
import com.securedeploy.ai.semantic.*;
import com.securedeploy.ai.dto.AiConfidence;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.test.util.ReflectionTestUtils;
import static org.assertj.core.api.Assertions.*;
import static com.securedeploy.project.progress.ReviewProgressSnapshot.*;

class ProgressComparisonEngineTest {
    final ProgressComparisonEngine engine = new ProgressComparisonEngine();
    final RiskPrioritizationEngine risk = new RiskPrioritizationEngine(new DefaultRiskPolicy());

    @Test void resolvedRemainingNewAndLineMovementUseEvidenceNotLine() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of()), code("A", 1), code("B", 2));
        var after = review(2, sca(ScaResult.Status.COMPLETE, List.of()), code("B", 200), code("C", 3));
        var snapshot = engine.compare(before, after);
        assertThat(snapshot.counts()).containsEntry(Change.RESOLVED, 1L).containsEntry(Change.REMAINING, 1L).containsEntry(Change.NEW, 1L);
        assertThat(snapshot.status()).isEqualTo(Status.COMPLETE);
        assertThat(snapshot.findings().stream().filter(e -> e.status() == Change.REMAINING).findFirst().orElseThrow().after().code().line()).isEqualTo(200);
    }
    @Test void failedAnalyzerMissingFileOrChangedAnalyzerNeverResolve() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of()), code("A", 1));
        for (var context : List.of(new ComparisonContext(1, 1L, "test-v1", false, List.of("application.yml")),
                new ComparisonContext(1, 1L, "test-v1", true, List.of()),
                new ComparisonContext(1, 1L, "test-v2", true, List.of("application.yml")))) {
            var after = review(2, sca(ScaResult.Status.COMPLETE, List.of()));
            after.attachComparisonContext(context);
            assertThat(engine.compare(before, after).counts()).containsEntry(Change.RESOLVED, 0L).containsEntry(Change.UNAVAILABLE, 1L);
        }
    }
    @ParameterizedTest @EnumSource(value = ScaResult.Status.class, names = {"PARTIAL", "UNAVAILABLE", "DISABLED", "NO_MANIFEST"})
    void dependencyLookupFailureOrUnresolvedNeverResolves(ScaResult.Status status) {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of(dependency("TEST-1", "1.0.0"))));
        var after = review(2, sca(status, List.of()));
        assertThat(engine.compare(before, after).counts()).containsEntry(Change.RESOLVED, 0L).containsEntry(Change.UNAVAILABLE, 1L);
    }
    @Test void completedLookupCanResolveButDoesNotChangeSavedRisk() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of(dependency("TEST-1", "1.0.0"))));
        var after = review(2, sca(ScaResult.Status.COMPLETE, List.of()));
        var original = after.getRiskAssessment();
        assertThat(engine.compare(before, after).counts()).containsEntry(Change.RESOLVED, 1L);
        assertThat(after.getRiskAssessment()).isSameAs(original);
    }
    @Test void advisoryAliasesMatchAcrossVersionChangesButDifferentAdvisoriesDoNotMerge() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of(dependency("OSV-TEST", "1.0.0"))));
        var after = review(2, sca(ScaResult.Status.COMPLETE, List.of(dependency("CVE-2099-0001", "1.0.1"))));
        assertThat(engine.compare(before, after).counts()).containsEntry(Change.CHANGED, 1L).containsEntry(Change.NEW, 0L);
    }
    @Test void duplicateMaskedAnchorsAreUnavailableNotCollapsed() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of()), code("A", 1), code("A", 2));
        var after = review(2, sca(ScaResult.Status.COMPLETE, List.of()), code("A", 5));
        var result = engine.compare(before, after);
        assertThat(result.counts()).containsEntry(Change.RESOLVED, 0L).containsEntry(Change.REMAINING, 0L).containsEntry(Change.UNAVAILABLE, 3L);
    }

    @Test void distinctAdvisoriesForOnePackageAreSeparateProblems() {
        var original = dependency("OSV-TEST", "1.0.0");
        var different = new DependencyVulnerability(ScaEcosystem.NPM, "fixture", "1.0.0", "OSV-OTHER", List.of("CVE-2099-0002"),
                "Another synthetic advisory", Severity.HIGH, null, List.of(), List.of("2.0.0"), null, null, List.of(), List.of("package.json"));
        var result = engine.compare(review(1, sca(ScaResult.Status.COMPLETE, List.of(original))),
                review(2, sca(ScaResult.Status.COMPLETE, List.of(original, different))));
        assertThat(result.counts()).containsEntry(Change.REMAINING, 1L).containsEntry(Change.NEW, 1L).containsEntry(Change.RESOLVED, 0L);
    }

    @Test void completeLabelWithoutCompleteLookupCountsCannotResolveDependency() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of(dependency("OSV-TEST", "1.0.0"))));
        var base = sca(ScaResult.Status.COMPLETE, List.of());
        var incomplete = new ScaResult(1, ScaResult.Status.COMPLETE, Instant.now(), new ScaResult.Summary(1, 0, 0, 0, 0, Map.of()),
                base.components(), List.of(), List.of());
        assertThat(engine.compare(before, review(2, incomplete)).counts()).containsEntry(Change.RESOLVED, 0L).containsEntry(Change.UNAVAILABLE, 1L);
    }
    @Test void missingHistoricalContextIsUnavailableAndNullBaselineDoesNotInventNewFindings() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of()), code("A", 1));
        before.attachComparisonContext(null);
        var after = review(2, sca(ScaResult.Status.COMPLETE, List.of()));
        assertThat(engine.compare(before, after).counts()).containsEntry(Change.RESOLVED, 0L);
        after.attachComparisonContext(after.getComparisonContext().withBaseline(null));
        assertThat(engine.compare(null, after).status()).isEqualTo(Status.NO_BASELINE);
        assertThat(engine.compare(null, after).findings()).isEmpty();
    }
    @Test void semanticDisappearanceIsNeverDeterministicResolutionAndCoverageIsRequired() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of()));
        var after = review(2, sca(ScaResult.Status.COMPLETE, List.of()));
        ReflectionTestUtils.setField(before, "semanticReview", semantic(true, SemanticSnapshot.Status.COMPLETED));
        ReflectionTestUtils.setField(after, "semanticReview", semantic(false, SemanticSnapshot.Status.COMPLETED));
        var result = engine.compare(before, after);
        assertThat(result.aiChanges().get(0).status()).isEqualTo(AiChange.NOT_REOBSERVED);
        assertThat(result.counts()).containsEntry(Change.RESOLVED, 0L);
        ReflectionTestUtils.setField(after, "semanticReview", semantic(false, SemanticSnapshot.Status.FAILED));
        assertThat(engine.compare(before, after).aiChanges().get(0).status()).isEqualTo(AiChange.UNAVAILABLE);
    }
    @Test void comparisonJsonRoundTripRetainsImmutableFactsAndNullCompatibility() {
        var snapshot = engine.compare(review(1, sca(ScaResult.Status.COMPLETE, List.of()), code("A", 1)),
                review(2, sca(ScaResult.Status.COMPLETE, List.of())));
        var converter = new ReviewProgressSnapshotConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(snapshot))).isEqualTo(snapshot);
        assertThat(converter.convertToEntityAttribute(null)).isNull();
    }
    @Test void structuralVersionChangeOrDisappearanceDoesNotBecomeAResolvedFinding() {
        var before = review(1, sca(ScaResult.Status.COMPLETE, List.of()));
        var after = review(2, sca(ScaResult.Status.COMPLETE, List.of()));
        var location = new com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.Location("worker.ts", 1, 1, "fetch", "D1_PREPARE");
        var finding = new com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.Finding("TS_SQL_INPUT_FLOW", "SQL_INPUT_TO_QUERY", "HIGH", "REVIEW_REQUIRED",
                location, location, List.of(location), List.of(), List.of(), "Synthetic", "Bind values");
        before.attachServerAnalysis(new com.securedeploy.analysis.typescript.ServerAnalysisSnapshot(1, "ts-server-v1", "6.0.3", "PARTIAL",
                List.of(), List.of(finding), List.of(), List.of(), List.of()));
        after.attachServerAnalysis(com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.unavailable("TIMEOUT", List.of(), "ANALYZER_TIMEOUT"));
        var result = engine.compare(before, after);
        assertThat(result.counts()).containsEntry(Change.RESOLVED, 0L).containsEntry(Change.NEW, 0L);
        assertThat(result.findings()).isEmpty();
        assertThat(result.notices()).anyMatch(n -> n.contains("서버 코드 흐름 Finding"));
    }
    ReviewEntity review(long id, ScaResult sca, VulnerabilityEntity... vulnerabilities) {
        var review = new ReviewEntity("test", ReviewSourceType.ZIP, null, 2, vulnerabilities.length, 100, "reference");
        ReflectionTestUtils.setField(review, "id", id);
        review.attachComparisonContext(new ComparisonContext(1, id == 1 ? null : 1L, "test-v1", true, List.of("application.yml", "package.json")));
        for (int i = 0; i < vulnerabilities.length; i++) {
            ReflectionTestUtils.setField(vulnerabilities[i], "id", id * 100 + i);
            review.addVulnerability(vulnerabilities[i]);
        }
        review.attachSca(sca);
        review.attachRiskAssessment(risk.assess(review.getVulnerabilities().stream().map(VulnerabilityResultResponse::from).toList(), sca));
        return review;
    }
    VulnerabilityEntity code(String rule, int line) {
        return new VulnerabilityEntity(rule, RuleCategory.CONFIGURATION, Severity.MEDIUM, "application.yml", line,
                "Synthetic finding", "Synthetic recommendation", "value=<redacted>", FalsePositiveRisk.LOW, DetectionConfidence.HIGH, "Test only");
    }
    ScaResult sca(ScaResult.Status status, List<DependencyVulnerability> findings) {
        return new ScaResult(1, status, Instant.now(), new ScaResult.Summary(1, 1, 0, findings.size(), findings.size(), Map.of()),
                List.of(new DependencyComponent(ScaEcosystem.NPM, "fixture", findings.isEmpty() ? "2.0.0" : findings.get(0).installedVersion(),
                        "dependencies", true, "package.json", 2, VersionResolution.EXACT)), findings, List.of());
    }
    DependencyVulnerability dependency(String id, String version) {
        return new DependencyVulnerability(ScaEcosystem.NPM, "fixture", version, id, List.of("CVE-2099-0001"), "Synthetic advisory",
                Severity.HIGH, null, List.of(), List.of("2.0.0"), null, null, List.of(), List.of("package.json"));
    }
    SemanticSnapshot semantic(boolean candidate, SemanticSnapshot.Status status) {
        var evidence = new SemanticCandidate.Evidence("context", "UserController.java", 1, 5, "getUser", "Synthetic context");
        var c = new SemanticCandidate("candidate", "slice", SemanticCandidate.CandidateType.IDOR, "Test", AiConfidence.MEDIUM,
                "Test reason", true, List.of(evidence), List.of("Check owner"), List.of(), Instant.now(), "template", "mock", "v1");
        var slice = new SecuritySlice.Metadata("slice", "getUser", "/user", "GET", "Unknown",
                List.of(new SecuritySlice.Location("UserController.java", 1, 5, "getUser")), List.of());
        return new SemanticSnapshot(1, "test", ScanMode.AI_ENHANCED, status, candidate ? List.of(c) : List.of(), List.of(),
                List.of(slice), 1, 0, 0, 0, "TEST", "template", "mock", "v1", Instant.now(), 0, null, List.of());
    }
}
