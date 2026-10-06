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
        assertThat(Files.exists(workspace)).isFalse();
    }
    private String signup() throws Exception {
        var request = mapper.writeValueAsBytes(Map.of("email", "sca-" + UUID.randomUUID() + "@test.invalid",
                "password", "Fake-test-password-1234", "name", "SCA Test"));
        return json(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    private JsonNode upload(String token) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("sca-fixture/package-lock.json"));
            zip.write(fixture("package-lock.json").getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
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
