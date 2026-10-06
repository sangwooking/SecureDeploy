package com.securedeploy.review;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityReviewFalsePositiveApiIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void zipUploadReturnsAdjustedMetadataAndDetailPreservesIt() throws Exception {
        String email = "fp-e2e-" + UUID.randomUUID() + "@test.invalid";
        JsonNode signup = signup(email);
        String token = signup.path("accessToken").asText();
        assertThat(token).isNotBlank();

        MockMultipartFile zip = new MockMultipartFile(
                "file",
                "fp-fixture.zip",
                "application/zip",
                zipFixture()
        );
        MvcResult uploadResult = mockMvc.perform(multipart("/api/reviews/upload")
                        .file(zip)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode uploadResponse = objectMapper.readTree(uploadResult.getResponse().getContentAsByteArray());
        long reviewId = uploadResponse.path("reviewId").asLong();
        assertThat(reviewId).isPositive();
        assertPlaceholderFinding(uploadResponse, "HARDCODED_PASSWORD");
        assertPlaceholderFinding(uploadResponse, "HARDCODED_SECRET");

        JsonNode detail = objectMapper.readTree(mockMvc.perform(get("/api/reviews/{reviewId}", reviewId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
        assertPlaceholderFinding(detail, "HARDCODED_PASSWORD");
        assertPlaceholderFinding(detail, "HARDCODED_SECRET");

        mockMvc.perform(delete("/api/reviews/{reviewId}", reviewId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk());
    }

    private JsonNode signup(String email) throws Exception {
        byte[] body = objectMapper.writeValueAsBytes(Map.of(
                "email", email,
                "password", "Fake-test-password-1234",
                "name", "FP Integration Test"
        ));
        return objectMapper.readTree(mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
    }

    private void assertPlaceholderFinding(JsonNode response, String ruleId) {
        JsonNode finding = null;
        for (JsonNode candidate : response.path("vulnerabilities")) {
            if (ruleId.equals(candidate.path("ruleId").asText())) {
                finding = candidate;
                break;
            }
        }
        assertThat(finding).isNotNull();
        assertThat(finding.path("falsePositiveRisk").asText()).isEqualTo("HIGH");
        assertThat(finding.path("confidence").asText()).isEqualTo("LOW");
        assertThat(finding.path("analysisNote").asText()).contains("placeholder");
        assertThat(finding.path("evidence").asText()).doesNotContain("changeme", "YOUR_SECRET_HERE");
    }

    private byte[] zipFixture() throws Exception {
        String config = "password=changeme\nsecret=YOUR_SECRET_HERE\n";
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("fp-fixture/application.properties"));
            zip.write(config.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return bytes.toByteArray();
    }
}
