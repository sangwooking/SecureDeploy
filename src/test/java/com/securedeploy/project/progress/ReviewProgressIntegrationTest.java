package com.securedeploy.project.progress;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.github.model.ClonedRepository;
import com.securedeploy.github.service.GitHubRepositoryService;
import com.securedeploy.persistence.service.ReviewPersistenceService;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.model.*;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"securedeploy.ai.provider=template", "securedeploy.sca.enabled=true"})
@AutoConfigureMockMvc
class ReviewProgressIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired ReviewPersistenceService persistence;
    @Autowired ReviewProgressService progress;
    @MockBean GitHubRepositoryService github;
    @MockBean VulnerabilityDataSource osv;
    @TempDir Path temp;
    String token;

    @BeforeEach void setup() throws Exception {
        when(github.validateAndNormalizeUrl(anyString())).thenCallRealMethod();
        when(osv.lookup(anyList())).thenAnswer(inv -> {
            List<DependencyComponent> components = inv.getArgument(0);
            return new VulnerabilityDataSource.LookupResult(List.of(), components.stream().map(DependencyComponent::identity).collect(java.util.stream.Collectors.toSet()), false, List.of());
        });
        token = signup();
    }
    String signup() throws Exception {
        var request = Map.of("email", "progress-" + UUID.randomUUID() + "@test.invalid", "password", "Fake-fixture-password-1234", "name", "Progress fixture");
        return mapper.readTree(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(request)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    MockMultipartFile archive(String name, boolean debug) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for (var entry : Map.of("application.properties", "debug=" + debug + "\nserver.error.include-stacktrace=always\n",
                    "package.json", "{\"name\":\"progress-fixture\",\"dependencies\":{\"fixture\":\"1.0.0\"}}").entrySet()) {
                zip.putNextEntry(new ZipEntry(name + "/" + entry.getKey()));
                zip.write(entry.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8)); zip.closeEntry();
            }
        }
        return new MockMultipartFile("file", name + ".zip", "application/zip", bytes.toByteArray());
    }
    JsonNode upload(Long project, String name, boolean debug) throws Exception {
        return mapper.readTree(mvc.perform(multipart(project == null ? "/api/reviews/upload" : "/api/projects/" + project + "/reviews/upload")
                .file(archive(name, debug)).header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode detail(long id) throws Exception {
        return mapper.readTree(mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    @Test void modifiedZipUsesSameProjectAndSnapshotIsStoredOnceIncludingHistoryAndDeletion() throws Exception {
        var first = upload(null, "before-" + UUID.randomUUID(), true);
        long project = first.path("projectId").asLong();
        var second = upload(project, "renamed-after", false);
        assertThat(second.path("projectId")).isEqualTo(first.path("projectId"));
        assertThat(second.path("reviewId")).isNotEqualTo(first.path("reviewId"));
        assertThat(second.at("/comparison/baselineReviewId")).isEqualTo(first.path("reviewId"));
        assertThat(second.at("/comparison/counts/RESOLVED").asInt()).isEqualTo(1);
        assertThat(second.at("/comparison/counts/REMAINING").asInt()).isGreaterThanOrEqualTo(1);
        var insight = mapper.readTree(mvc.perform(get("/api/projects/" + project + "/reviews/compare-latest/ai")
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(insight.path("deploymentReadinessOpinion").asText()).contains("위험 기반 배포 판단", "참고값");
        long id = second.path("reviewId").asLong();
        assertThat(detail(id).path("comparison")).isEqualTo(second.path("comparison"));
        progress.complete(persistence.findReviewDetail(id));
        assertThat(detail(id).path("comparison")).isEqualTo(second.path("comparison"));
        var third = upload(project, "third", true);
        assertThat(third.at("/comparison/counts/NEW").asInt()).isEqualTo(1);
        var history = mapper.readTree(mvc.perform(get("/api/reviews").header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
        var entry = java.util.stream.StreamSupport.stream(history.spliterator(), false).filter(h -> h.path("reviewId").asLong() == id).findFirst().orElseThrow();
        assertThat(entry.path("riskSummary").isObject()).isTrue();
        assertThat(entry.path("comparisonAvailable").asBoolean()).isTrue();
        mvc.perform(delete("/api/reviews/" + first.path("reviewId").asLong()).header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        assertThat(detail(id).path("comparison")).isEqualTo(second.path("comparison"));
        Files.writeString(Path.of("build/progress-review-fixture.json"), mapper.writeValueAsString(second));
    }
    @Test void legacyNullComparisonRemainsReadableAndFailedLookupCannotResolve() throws Exception {
        when(osv.lookup(anyList())).thenReturn(new VulnerabilityDataSource.LookupResult(List.of(new DependencyVulnerability(ScaEcosystem.NPM,
                "fixture", "1.0.0", "OSV-TEST-PROGRESS", List.of(), "Synthetic advisory", com.securedeploy.rule.model.Severity.HIGH,
                null, List.of(), List.of("2.0.0"), null, null, List.of(), List.of("package.json"))), Set.of("NPM|fixture|1.0.0"), false, List.of()));
        var first = upload(null, "dependency-" + UUID.randomUUID(), false);
        when(osv.lookup(anyList())).thenThrow(new IllegalStateException("Synthetic outage"));
        var second = upload(first.path("projectId").asLong(), "outage", false);
        assertThat(second.at("/comparison/counts/RESOLVED").asInt()).isZero();
        assertThat(second.at("/comparison/counts/UNAVAILABLE").asInt()).isGreaterThanOrEqualTo(1);
        assertThat(second.at("/sca/status").asText()).isEqualTo("UNAVAILABLE");
        mvc.perform(get("/api/projects/" + first.path("projectId").asLong() + "/reviews/compare-latest/ai")
                .header("Authorization", "Bearer " + token)).andExpect(status().isConflict());
        long id = first.path("reviewId").asLong();
        jdbc.update("update reviews set comparison_snapshot_json=null, comparison_context_json=null where id=?", id);
        assertThat(detail(id).path("comparison").isNull()).isTrue();
        var third = upload(first.path("projectId").asLong(), "legacy-next", false);
        assertThat(third.path("comparison").isObject()).isTrue();
    }
    @Test void githubRescanUsesRegisteredRepositoryAndRejectsOtherOwnerAndRepository() throws Exception {
        when(github.clonePublicRepository(anyString())).thenAnswer(inv -> {
            Path root = Files.createTempDirectory(temp, "clone-");
            Files.writeString(root.resolve("application.properties"), "debug=true\n");
            Files.writeString(root.resolve("package.json"), "{\"dependencies\":{}}");
            return new ClonedRepository("fixture", "https://github.com/fixture/progress.git", root, root);
        });
        var data = Map.of("repositoryUrl", "https://github.com/fixture/progress.git");
        var first = mapper.readTree(mvc.perform(post("/api/reviews/github").header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(data))).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        String endpoint = "/api/projects/" + first.path("projectId").asLong() + "/reviews/github";
        var second = mapper.readTree(mvc.perform(post(endpoint).header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(data))).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(second.path("projectId")).isEqualTo(first.path("projectId"));
        assertThat(second.at("/comparison/counts/REMAINING").asInt()).isPositive();
        mvc.perform(post(endpoint).header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
                .content("{\"repositoryUrl\":\"https://github.com/other/project\"}")).andExpect(status().isBadRequest());
        mvc.perform(post(endpoint).header("Authorization", "Bearer " + signup()).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(data))).andExpect(status().isForbidden());
        verify(github, times(2)).clonePublicRepository(anyString());
    }
}
