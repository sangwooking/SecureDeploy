package com.securedeploy.analysis.deployment;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.github.model.*;
import com.securedeploy.github.service.GitHubRepositoryService;
import com.securedeploy.github.app.PrivateGitHubSourceService;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import java.io.ByteArrayOutputStream;
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
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"securedeploy.ai.provider=template", "securedeploy.sca.enabled=false", "securedeploy.threat-intelligence.enabled=false"})
@AutoConfigureMockMvc
@Transactional
class DeploymentIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired jakarta.persistence.EntityManager entities;
    @MockBean GitHubRepositoryService github;
    @MockBean PrivateGitHubSourceService connected;
    @TempDir Path temp;
    Map<String,String> source(boolean risky) {
        return Map.of("compose.yaml", "services: {web: {user: '" + (risky ? "0" : "1000") + "'}}",
                "settings.py", "ROOT_URLCONF='app.urls'\nINSTALLED_APPS=[]\nDEBUG=" + (risky ? "True" : "False"),
                "wrangler.jsonc", "{\"vars\":{\"API_NAME\":\"public-description\"},\"env\":{\"preview\":{\"workers_dev\":true}}}");
    }
    @Test void allSourcesShareSnapshotsAndOwnershipWithoutRiskPromotionOrPaidAi() throws Exception {
        String token = signup();
        var zip = upload(token, source(true)); var safe = upload(token, source(false));
        var snapshot = zip.at("/serverAnalysis/deploymentAnalysis");
        assertThat(snapshot.path("findings")).hasSize(2);
        assertThat(snapshot.path("files")).hasSize(3);
        for (var f : snapshot.path("findings")) {
            assertThat(f.path("priority").asText()).isEqualTo("REVIEW_REQUIRED");
            assertThat(f.path("comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        }
        for (String key : List.of("securityScore", "vulnerabilityCount", "deploymentStatus")) assertThat(zip.path(key)).isEqualTo(safe.path(key));
        for (String key : List.of("prioritySummary", "prioritizedDeploymentAssessment", "codeFindings"))
            assertThat(zip.path("riskAssessment").path(key)).isEqualTo(safe.path("riskAssessment").path(key));
        assertThat(zip.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
        assertThat(zip.at("/coverage/analyzers").toString()).contains("DEPLOYMENT_CONFIG", "DJANGO:PARSED", "WRANGLER:PARSED");
        Path publicRoot = sourceDirectory("public");
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture", "https://github.com/fixture/config", publicRoot, publicRoot));
        var publicResult = postJson("/api/reviews/github", token, "{\"repositoryUrl\":\"https://github.com/fixture/config\",\"scanMode\":\"STANDARD\"}");
        Path privateRoot = sourceDirectory("private");
        var metadata = new GitHubSourceSnapshot("fixture", "config", "https://github.com/fixture/config", "main", "a".repeat(40), "aaaaaaa",
                null, null, null, null, 3, 0, 0, 0, List.of()).withAccess(123L, 456L, true);
        when(connected.collect(anyLong(), eq(456L), eq(123L))).thenReturn(new ClonedRepository("fixture", "https://github.com/fixture/config", privateRoot, privateRoot, metadata));
        var privateResult = postJson("/api/reviews/github/connected", token, "{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.at("/serverAnalysis/deploymentAnalysis")).isEqualTo(snapshot);
        assertThat(privateResult.at("/serverAnalysis/deploymentAnalysis")).isEqualTo(snapshot);
        assertThat(publicRoot).doesNotExist(); assertThat(privateRoot).doesNotExist();
        long id = zip.path("reviewId").asLong();
        assertThat(detail(token, id).at("/serverAnalysis/deploymentAnalysis")).isEqualTo(snapshot);
        assertThat(jdbc.queryForObject("select server_analysis_json from reviews where id=?", String.class, id)).doesNotContain("public-description", "app.urls");
        mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + signup())).andExpect(status().isForbidden());
        mvc.perform(get("/api/reviews").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews/" + id + "/report").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        jdbc.update("update reviews set server_analysis_json=null where id=?", id); entities.clear();
        assertThat(detail(token, id).path("serverAnalysis").isNull()).isTrue();
        assertThat(detail(token, id).path("riskAssessment")).isEqualTo(zip.path("riskAssessment"));
    }
    @Test void unsupportedConfigIsStoredAsIncompleteNotSafe() throws Exception {
        String token = signup(); var result = upload(token, Map.of("compose.yaml", "services: [", "wrangler.json", "{"));
        assertThat(result.at("/serverAnalysis/deploymentAnalysis/status").asText()).isEqualTo("PARTIAL");
        for (var f : result.at("/serverAnalysis/deploymentAnalysis/files")) assertThat(f.path("status").asText()).isEqualTo("PARSE_FAILED");
        assertThat(result.at("/serverAnalysis/deploymentAnalysis/findings")).isEmpty();
        assertThat(detail(token, result.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(result.path("serverAnalysis"));
    }
    Path sourceDirectory(String name) throws Exception {
        Path root = Files.createDirectory(temp.resolve(name));
        for (var file : source(true).entrySet()) Files.writeString(root.resolve(file.getKey()), file.getValue());
        return root;
    }
    String signup() throws Exception { return postJson("/api/auth/signup", null, json.writeValueAsString(Map.of(
            "email", UUID.randomUUID() + "@config-fixture.invalid", "password", UUID.randomUUID().toString(), "name", "Config fixture"))).path("accessToken").asText(); }
    JsonNode postJson(String path, String token, String body) throws Exception {
        var request = post(path).contentType(MediaType.APPLICATION_JSON).content(body);
        if (token != null) request.header("Authorization", "Bearer " + token);
        return json.readTree(mvc.perform(request).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode detail(String token, long id) throws Exception { return json.readTree(mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + token))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()); }
    JsonNode upload(String token, Map<String,String> files) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for (var file : files.entrySet()) { zip.putNextEntry(new ZipEntry("fixture/" + file.getKey())); zip.write(file.getValue().getBytes(StandardCharsets.UTF_8)); zip.closeEntry(); }
        }
        return json.readTree(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file", "fixture.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
}
