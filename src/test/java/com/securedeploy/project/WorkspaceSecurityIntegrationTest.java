package com.securedeploy.project;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.github.service.GitHubRepositoryService;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.persistence.repository.*;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.rule.model.*;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"securedeploy.ai.provider=template", "securedeploy.sca.enabled=false", "securedeploy.threat-intelligence.enabled=false"})
@AutoConfigureMockMvc
@Transactional
class WorkspaceSecurityIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired ProjectRepository projects;
    @Autowired ReviewRepository reviews;
    @Autowired UserRepository users;
    @MockBean GitHubRepositoryService github;
    String a, b;

    @BeforeEach void accounts() throws Exception { a = signup(); b = signup(); }
    String signup() throws Exception {
        return json.readTree(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(Map.of("email", UUID.randomUUID() + "@workspace.test.invalid",
                        "password", UUID.randomUUID().toString(), "name", "Workspace fixture"))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    MockMultipartFile zip(String name, boolean debug) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var out = new ZipOutputStream(bytes)) {
            out.putNextEntry(new ZipEntry(name + "/application.properties"));
            out.write(("debug=" + debug + "\nserver.error.include-stacktrace=always\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.closeEntry();
        }
        return new MockMultipartFile("file", name + ".zip", "application/zip", bytes.toByteArray());
    }
    JsonNode upload(String token, Long project, String name, boolean debug) throws Exception {
        return json.readTree(mvc.perform(multipart(project == null ? "/api/reviews/upload" : "/api/projects/" + project + "/reviews/upload")
                .file(zip(name, debug)).header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode getJson(String path, String token) throws Exception {
        return json.readTree(mvc.perform(get(path).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    @Test void dashboardAndHistoryUseOwnedSnapshotsAndRescansStayInProject() throws Exception {
        var first = upload(a, null, "workspace-" + UUID.randomUUID(), true);
        long project = first.path("projectId").asLong();
        var second = upload(a, project, "renamed-rescan", false);
        var other = upload(b, null, first.path("projectName").asText(), true);
        assertThat(other.path("projectId")).isNotEqualTo(first.path("projectId"));
        var workspace = getJson("/api/workspace", a);
        assertThat(workspace.path("projectCount").asInt()).isEqualTo(1);
        assertThat(workspace.path("analyzedProjectCount").asInt()).isEqualTo(1);
        var item = workspace.path("projects").get(0);
        assertThat(item.path("projectId").asLong()).isEqualTo(project);
        assertThat(item.path("reviewCount").asInt()).isEqualTo(2);
        assertThat(item.at("/latestReview/reviewId")).isEqualTo(second.path("reviewId"));
        assertThat(item.at("/latestReview/riskSummary/deploymentAssessment")).isEqualTo(second.at("/riskAssessment/prioritizedDeploymentAssessment"));
        assertThat(item.at("/latestReview/riskSummary/prioritySummary")).isEqualTo(second.at("/riskAssessment/prioritySummary"));
        assertThat(item.at("/latestProgress/counts")).isEqualTo(second.at("/comparison/counts"));
        assertThat(getJson("/api/projects", a)).hasSize(1);
        assertThat(getJson("/api/projects/" + project + "/reviews", a)).hasSize(2);
        assertThat(getJson("/api/reviews", b)).hasSize(1);
        mvc.perform(delete("/api/reviews/" + second.path("reviewId").asLong()).header("Authorization", "Bearer " + a)).andExpect(status().isOk());
        assertThat(getJson("/api/workspace", a).at("/projects/0/latestReview/reviewId")).isEqualTo(first.path("reviewId"));
    }

    @Test void anotherUserCannotReadChangeDeleteCompareOrRescanAnyOwnedResource() throws Exception {
        var review = upload(a, null, "private-" + UUID.randomUUID(), true);
        assertDenied(b, review.path("projectId").asLong(), review.path("reviewId").asLong(), review.at("/vulnerabilities/0/vulnerabilityId").asLong());
        assertThat(getJson("/api/workspace", b).path("projects")).isEmpty();
        assertThat(getJson("/api/reviews", b)).isEmpty();
        assertThat(getJson("/api/reviews/" + review.path("reviewId").asLong(), a).path("reviewId")).isEqualTo(review.path("reviewId"));
        verifyNoInteractions(github);
    }

    @Test void ownerlessLegacyRecordsArePreservedButHiddenAndInaccessible() throws Exception {
        var project = projects.saveAndFlush(new ProjectEntity("legacy-private", ReviewSourceType.ZIP, null));
        var review = legacyReview(project);
        assertDenied(a, project.getId(), review.getId(), review.getVulnerabilities().get(0).getId());
        var orphan = legacyReview(null);
        mvc.perform(get("/api/reviews/" + orphan.getId()).header("Authorization", "Bearer " + b)).andExpect(status().isForbidden());
        mvc.perform(patch("/api/vulnerabilities/" + orphan.getVulnerabilities().get(0).getId() + "/status")
                .header("Authorization", "Bearer " + b).contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"RESOLVED\"}"))
                .andExpect(status().isForbidden());
        assertThat(getJson("/api/reviews", a)).isEmpty();
        assertThat(getJson("/api/workspace", a).path("projects")).isEmpty();
        assertThat(projects.existsById(project.getId())).isTrue();
        assertThat(reviews.existsById(review.getId())).isTrue();
        assertThat(reviews.existsById(orphan.getId())).isTrue();
    }

    @Test void emptyAndLegacyOwnedProjectsAreUnassessedNotReady() throws Exception {
        var ownReview = upload(a, null, "empty-" + UUID.randomUUID(), false);
        long projectId = ownReview.path("projectId").asLong();
        mvc.perform(delete("/api/reviews/" + ownReview.path("reviewId").asLong()).header("Authorization", "Bearer " + a)).andExpect(status().isOk());
        var empty = getJson("/api/workspace", a);
        assertThat(empty.path("unassessedProjectCount").asInt()).isEqualTo(1);
        assertThat(empty.at("/projects/0/latestReview").isNull()).isTrue();
        legacyReview(projects.findById(projectId).orElseThrow());
        var legacy = getJson("/api/workspace", a);
        assertThat(legacy.path("unassessedProjectCount").asInt()).isEqualTo(1);
        assertThat(legacy.at("/projects/0/latestReview/riskSummary").isNull()).isTrue();
        mvc.perform(get("/api/workspace")).andExpect(status().isUnauthorized());
    }

    private ReviewEntity legacyReview(ProjectEntity project) {
        var r = new ReviewEntity("legacy", ReviewSourceType.ZIP, null, 1, 1, 100, "배포 가능");
        if (project != null) r.assignProject(project);
        r.addVulnerability(new VulnerabilityEntity("DEBUG_ENABLED", RuleCategory.CONFIGURATION, Severity.LOW,
                "application.properties", 1, "fixture", "fixture", "debug=true"));
        return reviews.saveAndFlush(r);
    }
    private void assertDenied(String token, long project, long review, long vulnerability) throws Exception {
        for (String suffix : List.of("", "/reviews", "/dashboard", "/vulnerabilities/status-summary", "/reviews/compare-latest", "/reviews/compare-latest/ai"))
            mvc.perform(get("/api/projects/" + project + suffix).header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        for (String suffix : List.of("", "/report", "/report/ai", "/ai-review", "/ai-summary", "/ai-remediation", "/ai-audit", "/ai-priorities", "/ai-roadmap"))
            mvc.perform(get("/api/reviews/" + review + suffix).header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        mvc.perform(patch("/api/vulnerabilities/" + vulnerability + "/status").header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"RESOLVED\",\"comment\":\"fixture\"}")).andExpect(status().isForbidden());
        mvc.perform(multipart("/api/projects/" + project + "/reviews/upload").file(zip("blocked", false)).header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        mvc.perform(post("/api/projects/" + project + "/reviews/github").header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content("{\"repositoryUrl\":\"https://github.com/fixture/project\"}")).andExpect(status().isForbidden());
        mvc.perform(delete("/api/reviews/" + review).header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        mvc.perform(delete("/api/projects/" + project).header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
    }
}
