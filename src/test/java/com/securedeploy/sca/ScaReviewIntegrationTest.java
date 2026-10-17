package com.securedeploy.sca;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.github.model.ClonedRepository;
import com.securedeploy.github.service.GitHubRepositoryService;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.model.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "securedeploy.sca.enabled=true")
@AutoConfigureMockMvc
class ScaReviewIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @MockBean VulnerabilityDataSource provider;
    @MockBean GitHubRepositoryService github;
    @org.springframework.boot.test.mock.mockito.SpyBean com.securedeploy.rule.engine.VulnerabilityRuleEngine ruleEngine;

    @BeforeEach void setup() {
        doAnswer(invocation -> {
            List<DependencyComponent> components = invocation.getArgument(0);
            var lodash = components.stream().filter(c -> c.packageName().equals("lodash")).findFirst().orElseThrow();
            var finding = new DependencyVulnerability(ScaEcosystem.NPM, "lodash", lodash.version(),
                    "GHSA-fixture-1", List.of("CVE-2099-0001"), "Offline test advisory", Severity.HIGH,
                    7.5, List.of(), List.of("4.17.21"), null, null, List.of(), List.of(lodash.sourceFile()));
            Set<String> identities = new HashSet<>();
            components.forEach(c -> identities.add(c.identity()));
            return new VulnerabilityDataSource.LookupResult(List.of(finding), identities, false, List.of());
        }).when(provider).lookup(anyList());
    }

    @Test void zipPersistsScaAndDeletionCascadesWithoutChangingTheExistingScore() throws Exception {
        String token = signup();
        JsonNode upload = upload(token);
        long review = upload.path("reviewId").asLong();
        assertThat(upload.path("deploymentAssessmentScope").asText()).isEqualTo("RULE_ENGINE_ONLY");
        assertThat(upload.at("/sca/status").asText()).isEqualTo("COMPLETE");
        assertThat(upload.at("/sca/summary/dependencyVulnerabilities").asInt()).isEqualTo(1);
        assertThat(upload.at("/sca/dependencyVulnerabilities/0/packageName").asText()).isEqualTo("lodash");
        JsonNode detail = json(mvc.perform(get("/api/reviews/" + review).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(detail.path("sca")).isEqualTo(upload.path("sca"));
        assertThat(detail.path("riskAssessment")).isEqualTo(upload.path("riskAssessment"));
        assertThat(upload.at("/riskAssessment/policyVersion").asText()).isEqualTo("risk-v1.2");
        assertThat(upload.at("/assessmentInterpretation/securityScoreDeterminesDeployment").asBoolean()).isFalse();
        assertThat(upload.at("/assessmentInterpretation/primaryAssessmentAvailable").asBoolean()).isTrue();
        assertThat(upload.at("/riskAssessment/dependencyFindings/0/priority").asText()).isEqualTo("SHOULD_FIX");
        assertThat(jdbc.queryForObject("select risk_assessment_json from reviews where id = ?", String.class, review)).contains("risk-v1");
        assertThat(jdbc.queryForObject("select count(*) from review_sca_reports where review_id = ?", Integer.class, review)).isEqualTo(1);
        String otherUser = signup();
        mvc.perform(get("/api/reviews/" + review).header("Authorization", "Bearer " + otherUser)).andExpect(status().isForbidden());

        doAnswer(invocation -> {
            List<DependencyComponent> cs = invocation.getArgument(0);
            Set<String> ids = new HashSet<>();
            cs.forEach(c -> ids.add(c.identity()));
            return new VulnerabilityDataSource.LookupResult(List.of(), ids, false, List.of());
        }).when(provider).lookup(anyList());
        JsonNode noAdvisory = upload(token);
        assertThat(noAdvisory.path("securityScore")).isEqualTo(upload.path("securityScore"));
        assertThat(noAdvisory.path("vulnerabilityCount")).isEqualTo(upload.path("vulnerabilityCount"));
        assertThat(noAdvisory.path("deploymentStatus")).isEqualTo(upload.path("deploymentStatus"));
        mvc.perform(delete("/api/reviews/" + review).header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        assertThat(jdbc.queryForObject("select count(*) from review_sca_reports where review_id = ?", Integer.class, review)).isZero();
        long project = noAdvisory.path("projectId").asLong();
        mvc.perform(delete("/api/projects/" + project).header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        assertThat(jdbc.queryForObject("select count(*) from review_sca_reports where review_id = ?", Integer.class,
                noAdvisory.path("reviewId").asLong())).isZero();
    }
    @Test void outageStillSavesRuleResultsAndUnavailableStatus() throws Exception {
        doThrow(new IllegalStateException("offline")).when(provider).lookup(anyList());
        String token = signup();
        JsonNode upload = upload(token);
        assertThat(upload.at("/sca/status").asText()).isEqualTo("UNAVAILABLE");
        assertThat(upload.path("reviewId").asLong()).isPositive();
        assertThat(upload.path("vulnerabilities").isArray()).isTrue();
        JsonNode detail = json(mvc.perform(get("/api/reviews/" + upload.path("reviewId").asLong())
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
        assertThat(detail.at("/sca/status").asText()).isEqualTo("UNAVAILABLE");
        assertThat(detail.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(detail.at("/riskAssessment/assessmentCoverage/sca").asText()).isEqualTo("FAILED");
        assertThat(detail.at("/riskAssessment/reviewRequirements/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
    }
    @Test void githubUsesTheSameStaticPipelineAndCleansItsWorkspace() throws Exception {
        Path workspace = Files.createTempDirectory("sca-github-fixture-");
        Files.writeString(workspace.resolve("package-lock.json"), fixture("package-lock.json"));
        when(github.clonePublicRepository("https://github.com/example/sca-fixture.git"))
                .thenReturn(new ClonedRepository("sca-fixture", "https://github.com/example/sca-fixture.git", workspace, workspace));
        String token = signup();
        JsonNode result = json(mvc.perform(post("/api/reviews/github")
                .header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
                .content("{\"repositoryUrl\":\"https://github.com/example/sca-fixture.git\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(result.at("/sca/status").asText()).isEqualTo("COMPLETE");
        assertThat(result.at("/sca/dependencyVulnerabilities/0/osvId").asText()).isEqualTo("GHSA-fixture-1");
        assertThat(result.at("/riskAssessment/dependencyFindings/0/priority").asText()).isEqualTo("SHOULD_FIX");
        assertThat(Files.exists(workspace)).isFalse();
    }

    @Test void codePrioritiesHaveStableSavedFindingIdsAndStatusChangesDoNotRewriteSnapshot() throws Exception {
        String token = signup();
        JsonNode result = upload(token, Map.of("package.json", "{\"name\":\"risk-fixture\",\"dependencies\":{}}",
                "application.properties", "secret=FakeOnly_A9c4E7h2K8m5P3q6R1t0U4v7W9x2Y5z8B6d3F1g0J4k7L9n2O5p8\n"));
        assertThat(result.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isEqualTo("BLOCKED");
        long vulnerability = result.at("/vulnerabilities/0/vulnerabilityId").asLong();
        assertThat(vulnerability).isPositive();
        assertThat(result.at("/riskAssessment/codeFindings/0/vulnerabilityId").asLong()).isEqualTo(vulnerability);
        assertThat(result.at("/riskAssessment/codeFindings/0/priority").asText()).isEqualTo("BLOCKING");
        mvc.perform(patch("/api/vulnerabilities/" + vulnerability + "/status")
                .header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
                .content("{\"status\":\"RESOLVED\",\"comment\":\"Test only\"}"))
                .andExpect(status().isOk());
        JsonNode detail = json(mvc.perform(get("/api/reviews/" + result.path("reviewId").asLong())
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
        assertThat(detail.path("riskAssessment")).isEqualTo(result.path("riskAssessment"));
        assertThat(detail.at("/vulnerabilities/0/status").asText()).isEqualTo("RESOLVED");
        mvc.perform(get("/api/reviews/" + result.path("reviewId").asLong() + "/ai-summary")
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews/" + result.path("reviewId").asLong() + "/report")
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
    }

    @Test void exactCriticalDependencyBlocksButDoesNotChangeRuleScore() throws Exception {
        doAnswer(invocation -> {
            List<DependencyComponent> components = invocation.getArgument(0);
            var c = components.get(0);
            var finding = new DependencyVulnerability(c.ecosystem(), c.packageName(), c.version(), "TEST-critical",
                    List.of(), "Fake advisory for policy test", Severity.CRITICAL, 9.8, List.of(), List.of(), null, null, List.of(), List.of(c.sourceFile()));
            return new VulnerabilityDataSource.LookupResult(List.of(finding), Set.of(c.identity()), false, List.of());
        }).when(provider).lookup(anyList());
        JsonNode result = upload(signup(), Map.of("package.json", "{\"name\":\"risk-fixture\",\"dependencies\":{\"fixture-policy-test\":\"1.0.0\"}}"));
        assertThat(result.path("securityScore").asInt()).isEqualTo(100);
        assertThat(result.path("deploymentStatus").asText()).isEqualTo("배포 가능");
        assertThat(result.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isEqualTo("BLOCKED");
        assertThat(result.at("/riskAssessment/dependencyFindings/0/priority").asText()).isEqualTo("BLOCKING");
    }

    @Test void unresolvedVersionIsNotReadyAndOldSnapshotStaysAbsent() throws Exception {
        String token = signup();
        JsonNode result = upload(token, Map.of("package.json", "{\"name\":\"risk-fixture\",\"dependencies\":{\"react\":\"^18.0.0\"}}"));
        assertThat(result.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(result.at("/riskAssessment/reviewRequirements/0/reasonCode").asText()).isEqualTo("UNRESOLVED_VERSION");
        jdbc.update("update reviews set risk_assessment_json = null where id = ?", result.path("reviewId").asLong());
        JsonNode old = json(mvc.perform(get("/api/reviews/" + result.path("reviewId").asLong()).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(old.path("riskAssessment").isNull()).isTrue();
        assertThat(old.at("/assessmentInterpretation/primaryAssessmentAvailable").asBoolean()).isFalse();
        assertThat(old.path("sca")).isEqualTo(result.path("sca"));
        assertThat(old.path("securityScore")).isEqualTo(result.path("securityScore"));
    }

    @Test void completedNoFindingReviewIsReadyAndPlaceholderRequiresReview() throws Exception {
        String token = signup();
        String manifest = "{\"name\":\"risk-fixture\",\"dependencies\":{}}";
        JsonNode clean = upload(token, Map.of("package.json", manifest));
        assertThat(clean.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isEqualTo("READY");
        JsonNode placeholder = upload(token, Map.of("package.json", manifest, "application.properties", "password=changeme\n"));
        assertThat(placeholder.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(placeholder.at("/riskAssessment/prioritySummary/BLOCKING").asInt()).isZero();
    }

    @Test void catalogProvenanceSurvivesFalsePositiveFilteringAndSnapshotReloadWithoutDoubleCounting() throws Exception {
        String token = signup();
        String manifest = """
                {
                  "dependencies": {
                    "lodash": "4.17.10"
                  }
                }
                """;
        JsonNode result = upload(token, Map.of("package.json", manifest));
        assertThat(result.path("vulnerabilities")).hasSize(1);
        assertThat(result.at("/riskAssessment/codeFindings")).isEmpty();
        assertThat(result.at("/riskAssessment/dependencyFindings")).hasSize(1);
        assertThat(result.at("/riskAssessment/dependencyCorrelations/0/relation").asText()).isEqualTo("PACKAGE_CANDIDATE_CONTEXT");
        assertThat(result.at("/riskAssessment/dependencyCorrelations/0/vulnerabilityId").asLong())
                .isEqualTo(result.at("/vulnerabilities/0/vulnerabilityId").asLong());
        assertThat(result.at("/riskAssessment/prioritySummaryBySource/CODE/REVIEW_REQUIRED").asInt()).isZero();
        assertThat(result.at("/riskAssessment/assessmentCoverage/threatIntelligence").asText()).isEqualTo("DISABLED");
        assertThat(result.at("/riskAssessment/prioritySummary/SHOULD_FIX").asInt()).isEqualTo(1);
        JsonNode detail = json(mvc.perform(get("/api/reviews/" + result.path("reviewId").asLong())
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(detail.path("riskAssessment")).isEqualTo(result.path("riskAssessment"));
        doAnswer(invocation -> {
            List<DependencyComponent> components = invocation.getArgument(0);
            return new VulnerabilityDataSource.LookupResult(List.of(), Set.of(components.get(0).identity()), false, List.of());
        }).when(provider).lookup(anyList());
        JsonNode unmatched = upload(token, Map.of("package.json", manifest));
        assertThat(unmatched.at("/riskAssessment/codeFindings")).hasSize(1);
        assertThat(unmatched.at("/riskAssessment/dependencyCorrelations")).isEmpty();
        assertThat(unmatched.path("securityScore")).isEqualTo(result.path("securityScore"));
        assertThat(unmatched.path("deploymentStatus")).isEqualTo(result.path("deploymentStatus"));
    }
    @Test void supplementalLookupIsUserProvidedAndNeverRewritesAnyReviewSnapshot() throws Exception {
        String token = signup();
        JsonNode before = upload(token, Map.of("package.json", "{\"dependencies\":{\"lodash\":\"^4.0.0\"}}"));
        JsonNode input = supplementalInput(before, "lodash", "4.17.10");
        String riskBefore = jdbc.queryForObject("select risk_assessment_json from reviews where id = ?", String.class, before.path("reviewId").asLong());
        JsonNode extra = supplement(token, before, input, 200);
        assertThat(extra.path("provenance").asText()).isEqualTo("USER_PROVIDED");
        assertThat(extra.path("status").asText()).isEqualTo("COMPLETE");
        assertThat(extra.at("/findings/0/fixedVersions/0").asText()).isEqualTo("4.17.21");
        assertUnchanged(token, before);
        assertThat(jdbc.queryForObject("select risk_assessment_json from reviews where id = ?", String.class, before.path("reviewId").asLong())).isEqualTo(riskBefore);
        verify(provider).lookup(argThat(cs -> cs.size() == 1 && cs.get(0).packageName().equals("lodash")
                && cs.get(0).version().equals("4.17.10") && cs.get(0).sourceFile().equals("user-provided")));
    }

    @Test void supplementalInputRejectsInjectionRangesIdentityChangesAndOtherOwners() throws Exception {
        String token = signup();
        JsonNode before = upload(token, Map.of("package.json", "{\"dependencies\":{\"lodash\":\"^4.0.0\"}}"));
        supplement(signup(), before, supplementalInput(before, "lodash", "4.17.10"), 403);
        for (String version : List.of("^4.0.0", "https://example.invalid", "1.0.0;echo", "1".repeat(129), "<script>")) {
            supplement(token, before, supplementalInput(before, "lodash", version), 400);
        }
        supplement(token, before, supplementalInput(before, "different-library", "1.0.0"), 400);
        supplement(token, before, supplementalInput(before, "<script>", "1.0.0"), 400);
        var forged = supplementalInput(before, "lodash", "4.17.10");
        ((com.fasterxml.jackson.databind.node.ObjectNode) forged).put("findingId", "coverage:sca");
        supplement(token, before, forged, 400);
        mvc.perform(post("/api/reviews/" + before.path("reviewId").asLong() + "/dependencies/supplemental-lookup")
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(forged)))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(provider);
        assertUnchanged(token, before);
    }

    @Test void missingPackageUsesStoredEcosystemAndFailureIsNeverComplete() throws Exception {
        String token = signup();
        JsonNode before = upload(token, Map.of("android/app/build.gradle.kts", "dependencies { implementation(libs.example.library) }"));
        assertThat(before.at("/sca/components/0/packageName").asText()).isEqualTo("<unresolved-package>");
        assertThat(before.at("/sca/components/0/version").isNull()).isTrue();
        var input = supplementalInput(before, "org.example:library", "1.0.0");
        doThrow(new IllegalStateException("offline fixture")).when(provider).lookup(anyList());
        assertThat(supplement(token, before, input, 200).path("status").asText()).isEqualTo("UNAVAILABLE");
        doAnswer(invocation -> {
            List<DependencyComponent> components = invocation.getArgument(0);
            DependencyComponent c = components.get(0);
            assertThat(c.ecosystem()).isEqualTo(ScaEcosystem.MAVEN);
            return new VulnerabilityDataSource.LookupResult(List.of(), Set.of(c.identity()), false, List.of());
        }).when(provider).lookup(anyList());
        JsonNode noHits = supplement(token, before, input, 200);
        assertThat(noHits.path("status").asText()).isEqualTo("COMPLETE");
        assertThat(noHits.path("findings")).isEmpty();
        assertUnchanged(token, before);
    }

    @Test void supplementalLookupPreservesPartialResultsAndLimitsRepeatRequests() throws Exception {
        String token = signup();
        JsonNode before = upload(token, Map.of("package.json", "{\"dependencies\":{\"lodash\":\"^4.0.0\"}}"));
        var input = supplementalInput(before, "lodash", "4.17.10");
        doAnswer(invocation -> {
            List<DependencyComponent> components = invocation.getArgument(0);
            DependencyComponent c = components.get(0);
            var partial = new DependencyVulnerability(c.ecosystem(), c.packageName(), c.version(), "TEST-partial",
                    List.of(), "Offline advisory", null, null, List.of(), List.of(), null, null, List.of(), List.of());
            return new VulnerabilityDataSource.LookupResult(List.of(partial), Set.of(c.identity()), true, List.of("Offline details"));
        }).when(provider).lookup(anyList());
        for (int i = 0; i < 6; i++) assertThat(supplement(token, before, input, 200).path("status").asText()).isEqualTo("PARTIAL");
        supplement(token, before, input, 429);
        verify(provider, times(6)).lookup(anyList());
        assertUnchanged(token, before);
    }

    @Test void pythonManualVersionLookupRetainsUserProvenanceAndNeverRewritesSavedAssessment() throws Exception {
        String token = signup();
        var before = upload(token, Map.of("requirements.txt", "Fixture_Python>=1.0", "server.py", "# synthetic, never executed"));
        assertThat(before.at("/sca/status").asText()).isEqualTo("PARTIAL");
        doAnswer(inv -> {
            List<DependencyComponent> list = inv.getArgument(0);
            assertThat(list).hasSize(1);
            assertThat(list.get(0).ecosystem()).isEqualTo(ScaEcosystem.PYPI);
            assertThat(list.get(0).packageName()).isEqualTo("fixture-python");
            assertThat(list.get(0).version()).isEqualTo("1!2.0");
            return new VulnerabilityDataSource.LookupResult(List.of(), Set.of(list.get(0).identity()), false, List.of());
        }).when(provider).lookup(anyList());
        var response = supplement(token, before, supplementalInput(before, "Fixture.Python", "1!2.0"), 200);
        assertThat(response.path("status").asText()).isEqualTo("COMPLETE");
        assertThat(response.path("packageName").asText()).isEqualTo("fixture-python");
        assertUnchanged(token, before);
        mvc.perform(get("/api/reviews/" + before.path("reviewId").asLong()).header("Authorization", "Bearer " + signup()))
                .andExpect(status().isForbidden());
    }

    private JsonNode supplementalInput(JsonNode review, String name, String version) {
        return mapper.valueToTree(Map.of("findingId", review.at("/riskAssessment/reviewRequirements/0/findingId").asText(),
                "packageName", name, "version", version));
    }
    private JsonNode supplement(String token, JsonNode review, JsonNode input, int expected) throws Exception {
        return json(mvc.perform(post("/api/reviews/" + review.path("reviewId").asLong() + "/dependencies/supplemental-lookup")
                .header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(input)))
                .andExpect(status().is(expected)).andReturn().getResponse().getContentAsByteArray());
    }
    private void assertUnchanged(String token, JsonNode before) throws Exception {
        JsonNode after = json(mvc.perform(get("/api/reviews/" + before.path("reviewId").asLong())
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(after).isEqualTo(before);
    }

    private String signup() throws Exception {
        var request = mapper.writeValueAsBytes(Map.of("email", "sca-" + UUID.randomUUID() + "@test.invalid",
                "password", "Fake-test-password-1234", "name", "SCA Test"));
        return json(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }

    @Test void coverageAndDependencyContextPersistRemainOwnerScopedAndDoNotBackfillHistory() throws Exception {
        String token = signup();
        String manifest = "{\"devDependencies\":{\"fixture-tool\":\"1.0.0\"}}";
        String lock = """
            {"lockfileVersion":3,"packages":{"":{"devDependencies":{"fixture-tool":"1.0.0"}},
            "node_modules/fixture-tool":{"version":"1.0.0","dev":true,"dependencies":{"lodash":"4.17.10"}},
            "node_modules/lodash":{"version":"4.17.10","dev":true}}}
            """;
        var result = upload(token, Map.of("package.json", manifest, "package-lock.json", lock,
                "worker.py", "synthetic", "wrangler.jsonc", "{}", "node_modules/ignored.js", "ignored"));
        assertThat(result.at("/coverage/discoveredFiles").asInt()).isEqualTo(5);
        assertThat(result.at("/coverage/unsupportedFiles").asInt()).isEqualTo(2);
        assertThat(result.at("/coverage/excludedFiles").asInt()).isEqualTo(1);
        assertThat(result.at("/sca/components/1/context/environment").asText()).isEqualTo("DEVELOPMENT");
        assertThat(result.at("/sca/components/1/context/paths/0/declarationFile").asText()).isEqualTo("package.json");
        long id = result.path("reviewId").asLong();
        assertUnchanged(token, result);
        mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + signup())).andExpect(status().isForbidden());
        assertThat(jdbc.queryForObject("select coverage_ledger_json from reviews where id=?", String.class, id)).doesNotContain("synthetic", "/tmp/", "ignored\"");
        jdbc.update("update reviews set coverage_ledger_json=null where id=?", id);
        var legacy = json(mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(legacy.path("coverage").isNull()).isTrue();
        assertThat(legacy.path("riskAssessment")).isEqualTo(result.path("riskAssessment"));
    }

    @Test void parsingFailureAndLookupFailureAreNotConfusedWithNoVulnerabilities() throws Exception {
        var malformed = upload(signup(), Map.of("package.json", "{not-json"));
        assertThat(malformed.at("/sca/manifests/0/status").asText()).isEqualTo("FAILED");
        assertThat(malformed.at("/sca/status").asText()).isEqualTo("PARTIAL");
        assertThat(malformed.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isEqualTo("REVIEW_REQUIRED");
        doThrow(new IllegalStateException("Offline fixture")).when(provider).lookup(anyList());
        var offline = upload(signup(), Map.of("package.json", "{\"dependencies\":{\"lodash\":\"4.17.10\"}}"));
        assertThat(offline.at("/sca/status").asText()).isEqualTo("UNAVAILABLE");
        assertThat(offline.at("/sca/manifests/0/status").asText()).isEqualTo("COMPLETE");
        assertThat(offline.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isNotEqualTo("READY");
    }

    @Test void unsupportedOnlyInputReturnsCoverageAndNeverCreatesASuccessfulReview() throws Exception {
        String token = signup();
        int before = jdbc.queryForObject("select count(*) from reviews", Integer.class);
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("fixture/server.py")); zip.write("synthetic".getBytes(StandardCharsets.UTF_8)); zip.closeEntry();
        }
        var error = json(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file", "fixture.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isBadRequest()).andReturn().getResponse().getContentAsByteArray());
        assertThat(error.at("/coverage/unsupportedFiles").asInt()).isEqualTo(1);
        assertThat(error.at("/coverage/selectedFiles").asInt()).isZero();
        assertThat(error.toString()).doesNotContain("synthetic", "/tmp/");
        assertThat(jdbc.queryForObject("select count(*) from reviews", Integer.class)).isEqualTo(before);
    }

    @Test void engineFailureReportsItsStageAndDoesNotExposeExceptionContentOrSaveAReview() throws Exception {
        String token = signup();
        int before = jdbc.queryForObject("select count(*) from reviews", Integer.class);
        doThrow(new IllegalStateException("synthetic-private-source-never-return")).when(ruleEngine).execute(any());
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("fixture/App.tsx")); zip.write("const fixture = 1;".getBytes(StandardCharsets.UTF_8)); zip.closeEntry();
        }
        var error = json(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file", "fixture.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isInternalServerError()).andReturn().getResponse().getContentAsByteArray());
        assertThat(error.at("/coverage/analyzers/0/analyzer").asText()).isEqualTo("RULE_ENGINE");
        assertThat(error.at("/coverage/status").asText()).isEqualTo("FAILED");
        assertThat(error.toString()).doesNotContain("synthetic-private-source", "/tmp/");
        assertThat(jdbc.queryForObject("select count(*) from reviews", Integer.class)).isEqualTo(before);
    }
    private JsonNode upload(String token) throws Exception {
        return upload(token, Map.of("package-lock.json", fixture("package-lock.json")));
    }
    private JsonNode upload(String token, Map<String, String> files) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            for (var file : files.entrySet()) {
                zip.putNextEntry(new ZipEntry("sca-fixture/" + file.getKey()));
                zip.write(file.getValue().getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return json(mvc.perform(multipart("/api/reviews/upload")
                .file(new MockMultipartFile("file", "sca-fixture.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
    }
    private String fixture(String name) throws Exception {
        return Files.readString(Path.of(getClass().getResource("/sca/" + name).toURI()));
    }
    private JsonNode json(byte[] bytes) throws Exception { return mapper.readTree(bytes); }
}
