package com.securedeploy.ai.remediation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.service.RealOpenAiProvider;
import com.securedeploy.ai.service.TemplateAiProvider;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "securedeploy.ai.provider=openai")
@AutoConfigureMockMvc
class RemediationReviewIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired com.securedeploy.persistence.service.ReviewPersistenceService persistence;
    @SpyBean RealOpenAiProvider openai;
    String token;

    @BeforeEach void setup() throws Exception {
        when(openai.providerType()).thenReturn(AiProviderType.OPENAI);
        when(openai.isAvailable()).thenReturn(true);
        when(openai.consumeLastTokenUsage()).thenReturn(Optional.empty());
        doAnswer(inv -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            return new TemplateAiProvider().generateFindingRemediations(inv.getArgument(0), null);
        }).when(openai).generateFindingRemediations(anyList(), any());
        var signup = Map.of("email", "remediation-" + UUID.randomUUID() + "@test.invalid", "password", "Fake-fixture-password-1234", "name", "Remediation fixture");
        token = mapper.readTree(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(signup))).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    @Test void storesSnapshotAfterRiskCommitAndHistoryNeverCallsProvider() throws Exception {
        var result = upload();
        long id = result.path("reviewId").asLong();
        assertThat(result.at("/remediation/findings").size()).isPositive();
        assertThat(result.at("/remediation/findings/0/generationStatus").asText()).isEqualTo("GENERATED");
        assertThat(jdbc.queryForObject("select remediation_snapshot_json from reviews where id=?", String.class, id)).contains("remediation-v1");
        clearInvocations(openai);
        var historical = detail(id);
        assertThat(historical.path("remediation")).isEqualTo(result.path("remediation"));
        assertThat(historical.path("riskAssessment")).isEqualTo(result.path("riskAssessment"));
        verifyNoInteractions(openai);
    }
    @Test void rescanGetsSeparateImmutableSnapshot() throws Exception {
        var first = upload();
        var second = upload();
        assertThat(first.path("projectId")).isEqualTo(second.path("projectId"));
        assertThat(first.at("/remediation/snapshotId")).isNotEqualTo(second.at("/remediation/snapshotId"));
        assertThat(detail(first.path("reviewId").asLong()).path("remediation")).isEqualTo(first.path("remediation"));
        assertThat(first.path("securityScore")).isEqualTo(second.path("securityScore"));
    }
    @Test void repeatedSnapshotSaveDoesNotOverwriteHistoricalAdviceOrRisk() throws Exception {
        var original = upload();
        long id = original.path("reviewId").asLong();
        var replacement = new RemediationSnapshot(1, UUID.randomUUID().toString(), java.time.Instant.now(),
                RemediationAdvice.GenerationStatus.UNAVAILABLE, List.of(), 0, List.of("Synthetic retry"), null);
        persistence.saveRemediationSnapshot(id, replacement);
        var historical = detail(id);
        assertThat(historical.path("remediation")).isEqualTo(original.path("remediation"));
        assertThat(historical.path("riskAssessment")).isEqualTo(original.path("riskAssessment"));
    }
    @Test void failurePreservesReviewRiskAndLegacyNullIsReadable() throws Exception {
        doThrow(new IllegalStateException("Synthetic provider unavailable")).when(openai).generateFindingRemediations(anyList(), any());
        var result = upload();
        assertThat(result.path("reviewId").asLong()).isPositive();
        assertThat(result.at("/remediation/findings/0/generationStatus").asText()).isEqualTo("TEMPLATE");
        assertThat(result.at("/riskAssessment/codeFindings/0/priority").asText()).isEqualTo("SHOULD_FIX");
        long id = result.path("reviewId").asLong();
        jdbc.update("update reviews set remediation_snapshot_json=null where id=?", id);
        clearInvocations(openai);
        var historical = detail(id);
        assertThat(historical.path("remediation").isNull()).isTrue();
        assertThat(historical.path("riskAssessment")).isEqualTo(result.path("riskAssessment"));
        verifyNoInteractions(openai);
    }
    @Test void deletingReviewAlsoRemovesRemediation() throws Exception {
        long id = upload().path("reviewId").asLong();
        mvc.perform(delete("/api/reviews/"+id).header("Authorization", "Bearer "+token)).andExpect(status().isOk());
        assertThat(jdbc.queryForObject("select count(*) from reviews where id=?", Integer.class, id)).isZero();
    }
    JsonNode detail(long id) throws Exception {
        return mapper.readTree(mvc.perform(get("/api/reviews/"+id).header("Authorization", "Bearer "+token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode upload() throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("remediation-fixture/src/main/resources/application.yml"));
            zip.write("debug: true\n".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return mapper.readTree(mvc.perform(multipart("/api/reviews/upload")
                .file(new MockMultipartFile("file", "remediation-fixture.zip", "application/zip", bytes.toByteArray()))
                .param("scanMode", "AI_ENHANCED")
                .header("Authorization", "Bearer "+token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
}
