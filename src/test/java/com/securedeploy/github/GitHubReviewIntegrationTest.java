package com.securedeploy.github;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.securedeploy.github.service.GitHubSnapshotFetcher;
import com.securedeploy.project.service.ProjectScanner;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.ai.semantic.SecuritySliceCollector;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.model.*;
import com.securedeploy.rule.model.Severity;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.eclipse.jgit.api.Git;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.*;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"securedeploy.ai.provider=template", "securedeploy.sca.enabled=true", "securedeploy.threat-intelligence.enabled=false"})
@AutoConfigureMockMvc
@Transactional
class GitHubReviewIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired jakarta.persistence.EntityManager entities;
    @Autowired SecuritySliceCollector slices;
    @SpyBean ProjectScanner scanner;
    @MockBean GitHubSnapshotFetcher fetcher;
    @MockBean VulnerabilityDataSource osv;
    @TempDir Path temp;
    String token, sha;
    final List<List<String>> fileSets = new ArrayList<>();
    final List<JsonNode> sliceSets = new ArrayList<>();
    final List<Path> workspaces = new ArrayList<>();

    @BeforeEach void setup() throws Exception {
        Path remote = temp.resolve("remote"); sha = GitSourceFixture.create(remote);
        when(fetcher.fetch(any(), any(), any())).thenAnswer(inv -> {
            Path dir = inv.getArgument(1); workspaces.add(dir.getParent());
            return GitSourceFixture.fetcher(remote).fetch(inv.getArgument(0), dir, inv.getArgument(2));
        });
        when(osv.lookup(anyList())).thenAnswer(inv -> {
            List<DependencyComponent> components = inv.getArgument(0);
            var lodash = components.stream().filter(c -> c.packageName().equals("lodash")).findFirst().orElseThrow();
            var finding = new DependencyVulnerability(ScaEcosystem.NPM, "lodash", lodash.version(), "OSV-OFFLINE-FIXTURE",
                    List.of(), "Offline consistency advisory", Severity.HIGH, null, List.of(), List.of("4.17.21"), null, null, List.of(), List.of(lodash.sourceFile()));
            return new VulnerabilityDataSource.LookupResult(List.of(finding), components.stream().map(DependencyComponent::identity).collect(java.util.stream.Collectors.toSet()), false, List.of());
        });
        doAnswer(inv -> {
            ProjectStructure result = (ProjectStructure) inv.callRealMethod();
            fileSets.add(result.analysisFiles().stream().map(f -> f.relativePath()).sorted().toList());
            sliceSets.add(json.valueToTree(slices.collect(result).slices()));
            return result;
        }).when(scanner).scan(any());
        token = signup();
    }
    @Test void zipAndGitShareScannedFilesRulesDependenciesPrioritiesAndSemanticInput() throws Exception {
        var github = github(null, "https://github.com/Fixture/Monorepo.git");
        var zip = upload();
        assertThat(fileSets.get(0)).isEqualTo(fileSets.get(1));
        assertThat(fileSets.get(0)).contains("backend/module/pom.xml", "services/sub/build.gradle.kts", "frontend/widget/package.json",
                "deploy/Dockerfile", "deploy/k8s/custom.yaml", "frontend/.env.production").noneMatch(p -> p.startsWith("build/") || p.contains("node_modules"));
        assertThat(sliceSets.get(0)).isEqualTo(sliceSets.get(1));
        assertThat(rules(github)).isEqualTo(rules(zip));
        assertThat(github.path("scannedFileCount")).isEqualTo(zip.path("scannedFileCount"));
        assertThat(github.path("securityScore")).isEqualTo(zip.path("securityScore"));
        assertThat(github.at("/sca/summary")).isEqualTo(zip.at("/sca/summary"));
        assertThat(github.at("/sca/dependencyVulnerabilities")).isEqualTo(zip.at("/sca/dependencyVulnerabilities"));
        assertThat(github.at("/riskAssessment/prioritySummary")).isEqualTo(zip.at("/riskAssessment/prioritySummary"));
        assertThat(github.at("/riskAssessment/prioritizedDeploymentAssessment")).isEqualTo(zip.at("/riskAssessment/prioritizedDeploymentAssessment"));
        assertThat(github.at("/sourceMetadata/analyzedBranch").asText()).isEqualTo("develop");
        assertThat(github.at("/sourceMetadata/commitSha").asText()).isEqualTo(sha);
        assertThat(zip.path("sourceMetadata").isNull()).isTrue();
        workspaces.forEach(path -> assertThat(path).doesNotExist());
    }
    @Test void canonicalIdentityRescansAndComparisonFreezeTheExactSourceVersion() throws Exception {
        var first = github(null, "https://github.com/fixture/monorepo.git");
        long project = first.path("projectId").asLong();
        // A previously stored case/suffix spelling must not create a duplicate project.
        jdbc.update("update projects set repository_url=? where id=?", "https://github.com/Fixture/Monorepo.git/", project);
        entities.clear();
        var same = github(null, "https://github.com/FIXTURE/MONOREPO");
        assertThat(same.path("projectId")).isEqualTo(first.path("projectId"));
        assertThat(same.path("reviewId")).isNotEqualTo(first.path("reviewId"));
        assertThat(same.at("/comparison/sourceBefore/commitSha").asText()).isEqualTo(sha);
        assertThat(same.at("/comparison/sourceAfter/commitSha").asText()).isEqualTo(sha);
        Files.writeString(temp.resolve("remote/backend/src/main/resources/application.properties"), "debug=false\nserver.error.include-stacktrace=always\n");
        String nextSha;
        try (Git git = Git.open(temp.resolve("remote").toFile())) { nextSha = GitSourceFixture.commit(git); }
        var next = github(project, "https://github.com/fixture/monorepo");
        assertThat(next.at("/sourceMetadata/commitSha").asText()).isEqualTo(nextSha).isNotEqualTo(sha);
        assertThat(next.at("/comparison/sourceBefore/commitSha").asText()).isEqualTo(sha);
        assertThat(next.at("/comparison/counts/RESOLVED").asInt()).isPositive();
        assertThat(detail(first.path("reviewId").asLong()).path("sourceMetadata")).isEqualTo(first.path("sourceMetadata"));
        assertThat(detail(next.path("reviewId").asLong()).path("comparison")).isEqualTo(next.path("comparison"));
        var history = read("/api/projects/" + project + "/reviews");
        assertThat(history.get(0).path("sourceMetadata")).isEqualTo(next.path("sourceMetadata"));
        var workspace = read("/api/workspace");
        assertThat(workspace.at("/projects/0/latestReview/sourceMetadata")).isEqualTo(next.path("sourceMetadata"));
        // Baseline deletion must not remove the before-commit stored inside the comparison snapshot.
        mvc.perform(delete("/api/reviews/" + same.path("reviewId").asLong()).header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        assertThat(detail(next.path("reviewId").asLong()).at("/comparison/sourceBefore/commitSha").asText()).isEqualTo(sha);
        String other = signup();
        mvc.perform(post("/api/projects/" + project + "/reviews/github").header("Authorization", "Bearer " + other)
                .contentType(MediaType.APPLICATION_JSON).content("{\"repositoryUrl\":\"https://github.com/fixture/monorepo\"}"))
                .andExpect(status().isForbidden());
        verify(fetcher, times(3)).fetch(any(), any(), any());
        jdbc.update("update reviews set source_metadata_json=null where id=?", first.path("reviewId").asLong());
        entities.clear();
        assertThat(detail(first.path("reviewId").asLong()).path("sourceMetadata").isNull()).isTrue();
        workspaces.forEach(path -> assertThat(path).doesNotExist());
    }
    @Test void postCloneAnalysisFailureCleansWorkspaceAndDoesNotSaveReview() throws Exception {
        doThrow(new IllegalStateException("Offline analysis failure")).when(scanner).scan(any());
        int before = jdbc.queryForObject("select count(*) from reviews", Integer.class);
        mvc.perform(post("/api/reviews/github").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
                .content("{\"repositoryUrl\":\"https://github.com/fixture/monorepo\"}")).andExpect(status().isInternalServerError());
        assertThat(jdbc.queryForObject("select count(*) from reviews", Integer.class)).isEqualTo(before);
        workspaces.forEach(path -> assertThat(path).doesNotExist());
    }
    String signup() throws Exception {
        return json.readTree(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(Map.of("email", UUID.randomUUID() + "@source.test.invalid", "password", UUID.randomUUID().toString(), "name", "Source fixture"))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    JsonNode github(Long project, String url) throws Exception {
        return json.readTree(mvc.perform(post(project == null ? "/api/reviews/github" : "/api/projects/" + project + "/reviews/github")
                .header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsBytes(Map.of("repositoryUrl", url))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode upload() throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for (var entry : GitSourceFixture.FILES.entrySet()) {
                zip.putNextEntry(new ZipEntry("monorepo/" + entry.getKey())); zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8)); zip.closeEntry();
            }
        }
        return json.readTree(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file", "monorepo.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode read(String path) throws Exception { return json.readTree(mvc.perform(get(path).header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()); }
    JsonNode detail(long id) throws Exception { return read("/api/reviews/" + id); }
    List<String> rules(JsonNode result) {
        var values = new ArrayList<String>();
        result.path("vulnerabilities").forEach(value -> {
            var copy = ((ObjectNode)value).deepCopy(); copy.remove(List.of("vulnerabilityId", "statusUpdatedAt")); values.add(copy.toString());
        });
        return values.stream().sorted().toList();
    }
}
