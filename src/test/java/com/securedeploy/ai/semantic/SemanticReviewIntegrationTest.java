package com.securedeploy.ai.semantic;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.service.*;
import com.securedeploy.github.model.ClonedRepository;
import com.securedeploy.github.service.GitHubRepositoryService;
import com.securedeploy.persistence.service.ReviewPersistenceService;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
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
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "securedeploy.ai.provider=openai")
@AutoConfigureMockMvc
class SemanticReviewIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired ReviewPersistenceService persistence;
    @SpyBean RealOpenAiProvider openai;
    @MockBean GitHubRepositoryService github;
    @TempDir Path temp;
    String token;
    @BeforeEach void setup() throws Exception {
        when(github.validateAndNormalizeUrl(anyString())).thenCallRealMethod();
        when(openai.isAvailable()).thenReturn(true);
        when(openai.providerType()).thenReturn(AiProviderType.OPENAI);
        when(openai.consumeLastTokenUsage()).thenReturn(Optional.empty());
        doAnswer(inv -> new TemplateAiProvider().generateFindingRemediations(inv.getArgument(0),null))
                .when(openai).generateFindingRemediations(anyList(),any());
        doAnswer(inv -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            List<SecuritySlice> slices = inv.getArgument(0);
            assertThat(slices.toString()).doesNotContain("fixture-only-never-valid-credential");
            var user = slices.stream().filter(s -> s.entryPoint().startsWith("UserController")).findFirst().orElseThrow();
            var file = slices.stream().filter(s -> s.entryPoint().startsWith("FileController")).findFirst().orElseThrow();
            return List.of(SemanticReviewTest.proposal(user,SemanticCandidate.CandidateType.IDOR),
                    SemanticReviewTest.proposal(file,SemanticCandidate.CandidateType.PATH_TRAVERSAL_CANDIDATE));
        }).when(openai).generateSemanticReview(anyList(),any());
        token = signup();
        clearInvocations(openai);
    }
    String signup() throws Exception {
        var body = Map.of("email","semantic-"+UUID.randomUUID()+"@test.invalid","password","Fake-fixture-password-1234","name","Semantic fixture");
        return mapper.readTree(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    JsonNode upload(String mode, Long projectId) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for (var file : SemanticReviewTest.fixtures().analysisFiles()) {
                zip.putNextEntry(new ZipEntry("semantic-fixture/src/main/java/fixture/"+file.relativePath()));
                zip.write(Files.readAllBytes(file.absolutePath())); zip.closeEntry();
            }
        }
        var request = multipart(projectId==null ? "/api/reviews/upload" : "/api/projects/"+projectId+"/reviews/upload")
                .file(new MockMultipartFile("file","semantic-fixture.zip","application/zip",bytes.toByteArray()));
        if (mode!=null) request.param("scanMode",mode);
        return mapper.readTree(mvc.perform(request.header("Authorization","Bearer "+token)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode detail(long id) throws Exception {
        return mapper.readTree(mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    @Test void defaultStandardNeverCallsAiAndEnhancedPersistsSeparately() throws Exception {
        var standard = upload(null,null);
        assertThat(standard.at("/semanticReview/scanMode").asText()).isEqualTo("STANDARD");
        assertThat(standard.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
        assertThat(standard.path("scanMode").asText()).isEqualTo("STANDARD");
        for (String suffix : List.of("ai-review","ai-summary","ai-remediation","ai-audit","ai-priorities","ai-roadmap","report","report/ai"))
            mvc.perform(get("/api/reviews/"+standard.path("reviewId").asLong()+"/"+suffix).header("Authorization","Bearer "+token)).andExpect(status().isOk());
        verifyNoInteractions(openai);
        var enhanced = upload("AI_ENHANCED",standard.path("projectId").asLong());
        assertThat(enhanced.at("/semanticReview/candidates").size()).isEqualTo(2);
        assertThat(enhanced.path("scanMode").asText()).isEqualTo("AI_ENHANCED");
        Files.writeString(Path.of("build/semantic-review-fixture.json"), mapper.writeValueAsString(enhanced));
        assertThat(enhanced.at("/semanticReview/candidates/0/reviewStatus").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(enhanced.path("securityScore")).isEqualTo(standard.path("securityScore"));
        assertThat(enhanced.path("vulnerabilityCount")).isEqualTo(standard.path("vulnerabilityCount"));
        assertThat(enhanced.at("/riskAssessment/prioritySummary")).isEqualTo(standard.at("/riskAssessment/prioritySummary"));
        assertThat(enhanced.at("/riskAssessment/prioritizedDeploymentAssessment")).isEqualTo(standard.at("/riskAssessment/prioritizedDeploymentAssessment"));
        long id = enhanced.path("reviewId").asLong();
        assertStoredSnapshotMatchesApi(id, enhanced.path("semanticReview"));
        clearInvocations(openai);
        assertThat(detail(id).path("semanticReview")).isEqualTo(enhanced.path("semanticReview"));
        mvc.perform(get("/api/reviews").header("Authorization","Bearer "+token)).andExpect(status().isOk());
        verifyNoInteractions(openai);
    }
    private void assertStoredSnapshotMatchesApi(long id, JsonNode apiSnapshot) throws Exception {
        String stored = jdbc.queryForObject("select semantic_snapshot_json from reviews where id=?",String.class,id);
        var raw = mapper.readTree(stored);
        // The JPA converter uses numeric timestamps; Spring's API mapper uses ISO strings.
        assertThat(raw.path("generatedAt").isNumber()).isTrue();
        assertThat(apiSnapshot.path("generatedAt").isTextual()).isTrue();
        var decoded = new SemanticSnapshotConverter().convertToEntityAttribute(stored);
        JsonNode normalized = mapper.readTree(mapper.writeValueAsBytes(decoded));
        assertThat(normalized).isEqualTo(apiSnapshot);
    }
    @Test void completedEmptyModelResponseIsStoredWithoutClaimingSafety() throws Exception {
        doReturn(List.of()).when(openai).generateSemanticReview(anyList(),any());
        var result = upload("AI_ENHANCED",null);
        long id = result.path("reviewId").asLong();
        var snapshot = result.path("semanticReview");
        assertThat(snapshot.path("semanticReviewStatus").asText()).isEqualTo("COMPLETED");
        assertThat(snapshot.path("candidates").size()).isZero();
        assertThat(snapshot.path("validationStatus").asText()).isEqualTo("LOCATION_VALIDATED_NOT_SECURITY_PROVEN");
        assertStoredSnapshotMatchesApi(id,snapshot);
        clearInvocations(openai);
        assertThat(detail(id).path("semanticReview")).isEqualTo(snapshot);
        verifyNoInteractions(openai);
    }
    @Test void rescanIsNewSnapshotAndHistoryCannotBeOverwritten() throws Exception {
        var first = upload("AI_ENHANCED",null); var second = upload("AI_ENHANCED",null);
        assertThat(first.at("/semanticReview/snapshotId")).isNotEqualTo(second.at("/semanticReview/snapshotId"));
        persistence.saveSemanticSnapshot(first.path("reviewId").asLong(),mapper.treeToValue(second.path("semanticReview"),SemanticSnapshot.class));
        assertThat(detail(first.path("reviewId").asLong()).path("semanticReview")).isEqualTo(first.path("semanticReview"));
    }
    @Test void providerFailureRetainsReviewAndLegacyNullHistory() throws Exception {
        doThrow(new IllegalStateException("synthetic failure")).when(openai).generateSemanticReview(anyList(),any());
        var failed = upload("AI_ENHANCED",null); long id=failed.path("reviewId").asLong();
        assertThat(failed.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("FAILED");
        assertThat(failed.path("riskAssessment").isObject()).isTrue();
        jdbc.update("update reviews set semantic_snapshot_json=null where id=?",id);
        clearInvocations(openai);
        assertThat(detail(id).path("semanticReview").isNull()).isTrue(); verifyNoInteractions(openai);
    }
    @Test void githubModesAndProjectRoutesSharePipelineWithoutExternalClone() throws Exception {
        Path project=temp.resolve("project"); Files.createDirectories(project);
        for (var file : SemanticReviewTest.fixtures().analysisFiles()) Files.copy(file.absolutePath(),project.resolve(file.relativePath()));
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("semantic-github","https://github.com/fixture/semantic.git",project,project));
        var data=Map.of("repositoryUrl","https://github.com/fixture/semantic.git","scanMode","AI_ENHANCED");
        var result=mapper.readTree(mvc.perform(post("/api/reviews/github").header("Authorization","Bearer "+token)
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(data))).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertThat(result.at("/semanticReview/candidates").size()).isEqualTo(2);
        Files.createDirectories(project);
        for (var file : SemanticReviewTest.fixtures().analysisFiles()) Files.copy(file.absolutePath(),project.resolve(file.relativePath()));
        clearInvocations(openai);
        mvc.perform(post("/api/projects/"+result.path("projectId").asLong()+"/reviews/github").header("Authorization","Bearer "+token)
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(Map.of("repositoryUrl",data.get("repositoryUrl")))))
                .andExpect(status().isOk());
        verifyNoInteractions(openai);
    }
    @Test void deletionRemovesSnapshotAndOtherUserCannotReadIt() throws Exception {
        long id=upload("AI_ENHANCED",null).path("reviewId").asLong();
        String other=signup();
        int code=mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+other)).andReturn().getResponse().getStatus();
        assertThat(code).isIn(403,404);
        mvc.perform(delete("/api/reviews/"+id).header("Authorization","Bearer "+token)).andExpect(status().isOk());
        assertThat(jdbc.queryForObject("select count(*) from reviews where id=?",Integer.class,id)).isZero();
    }
    @Test void invalidScanModesAreBadRequestsNotServerErrors() throws Exception {
        mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file","test.zip","application/zip",new byte[]{1}))
                .param("scanMode","INVALID").header("Authorization","Bearer "+token)).andExpect(status().isBadRequest());
        mvc.perform(post("/api/reviews/github").header("Authorization","Bearer "+token).contentType(MediaType.APPLICATION_JSON)
                .content("{\"repositoryUrl\":\"https://github.com/fixture/semantic\",\"scanMode\":\"INVALID\"}"))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(openai);
    }
}
