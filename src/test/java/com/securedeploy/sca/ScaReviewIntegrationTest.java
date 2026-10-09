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
    private String signup() throws Exception {
        var request = mapper.writeValueAsBytes(Map.of("email", "sca-" + UUID.randomUUID() + "@test.invalid",
                "password", "Fake-test-password-1234", "name", "SCA Test"));
        return json(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
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
