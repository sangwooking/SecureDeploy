package com.securedeploy.analysis.typescript;

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
class ServerAnalysisIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired jakarta.persistence.EntityManager entities;
    @MockBean GitHubRepositoryService github;
    @MockBean PrivateGitHubSourceService connected;
    @TempDir Path temp;

    @Test void zipPublicAndPrivateShareEvidencePersistenceAndCleanupWithoutChangingRisk() throws Exception {
        String token = signup();
        var zip = upload(token, TypeScriptServerAnalyzerTest.UNSAFE);
        var safe = upload(token, TypeScriptServerAnalyzerTest.SAFE);
        assertThat(zip.at("/serverAnalysis/findings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/validatedFindings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/executionLocations")).isNotEmpty();
        assertThat(safe.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.at("/serverAnalysis/findings")).isEmpty();
        for (String key : List.of("securityScore", "vulnerabilityCount", "deploymentStatus")) assertThat(zip.path(key)).isEqualTo(safe.path(key));
        for (String key : List.of("prioritySummary", "prioritizedDeploymentAssessment", "codeFindings"))
            assertThat(zip.path("riskAssessment").path(key)).isEqualTo(safe.path("riskAssessment").path(key));
        assertThat(zip.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
        Path publicRoot = source("public");
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture", "https://github.com/fixture/server", publicRoot, publicRoot));
        var publicResult = postJson("/api/reviews/github", token, "{\"repositoryUrl\":\"https://github.com/fixture/server\",\"scanMode\":\"STANDARD\"}");
        Path privateRoot = source("private");
        var metadata = new GitHubSourceSnapshot("fixture", "server", "https://github.com/fixture/server", "main", "a".repeat(40), "aaaaaaa",
                null, null, null, null, 1, 0, 0, 0, List.of()).withAccess(123L, 456L, true);
        when(connected.collect(anyLong(), eq(456L), eq(123L))).thenReturn(new ClonedRepository("fixture", "https://github.com/fixture/server", privateRoot, privateRoot, metadata));
        var privateResult = postJson("/api/reviews/github/connected", token, "{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(privateResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(publicRoot).doesNotExist(); assertThat(privateRoot).doesNotExist();
        long id = zip.path("reviewId").asLong();
        assertThat(detail(token, id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(jdbc.queryForObject("select server_analysis_json from reviews where id=?", String.class, id))
                .contains("TS_SQL_INPUT_FLOW", "ts-flow:", "verificationSteps").doesNotContain("SELECT *");
        mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + signup())).andExpect(status().isForbidden());
        mvc.perform(get("/api/reviews").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews/" + id + "/report").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews/" + id + "/ai-summary").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        jdbc.update("update reviews set server_analysis_json=null where id=?", id); entities.clear();
        assertThat(detail(token, id).path("serverAnalysis").isNull()).isTrue();
        assertThat(detail(token, id).path("riskAssessment")).isEqualTo(zip.path("riskAssessment"));
    }
    @Test void syntaxFailureIsStoredAsIncompleteWithoutInventingFindings() throws Exception {
        String token = signup(); var result = upload(token, "export default { fetch( {");
        assertThat(result.at("/serverAnalysis/status").asText()).isEqualTo("PARTIAL");
        assertThat(result.at("/serverAnalysis/files/0/parseStatus").asText()).isEqualTo("PARSE_FAILED");
        assertThat(result.at("/serverAnalysis/findings")).isEmpty();
        assertThat(result.path("coverage").path("analyzers").toString()).contains("TYPESCRIPT_SERVER", "AST_PARSE_FAILED");
        assertThat(detail(token, result.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(result.path("serverAnalysis"));
    }
    Path source(String dir) throws Exception {
        Path root = Files.createDirectory(temp.resolve(dir)); Files.writeString(root.resolve("worker.ts"), TypeScriptServerAnalyzerTest.UNSAFE); return root;
    }
    String signup() throws Exception { return postJson("/api/auth/signup", null, json.writeValueAsString(Map.of(
            "email", UUID.randomUUID() + "@ts-fixture.invalid", "password", UUID.randomUUID().toString(), "name", "AST fixture"))).path("accessToken").asText(); }
    JsonNode postJson(String path, String token, String body) throws Exception {
        var request = post(path).contentType(MediaType.APPLICATION_JSON).content(body);
        if (token != null) request.header("Authorization", "Bearer " + token);
        return json.readTree(mvc.perform(request).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode detail(String token, long id) throws Exception { return json.readTree(mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + token))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()); }
    JsonNode upload(String token, String code) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) { zip.putNextEntry(new ZipEntry("fixture/worker.ts")); zip.write(code.getBytes(StandardCharsets.UTF_8)); zip.closeEntry(); }
        return json.readTree(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file", "fixture.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
}
