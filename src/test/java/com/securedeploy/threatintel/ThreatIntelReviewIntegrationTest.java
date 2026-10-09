package com.securedeploy.threatintel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.model.*;
import com.securedeploy.threatintel.client.*;
import com.securedeploy.threatintel.model.LookupStatus;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.*;
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
import static org.mockito.ArgumentMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static com.securedeploy.threatintel.ThreatFixtures.*;

@SpringBootTest(properties = {"securedeploy.sca.enabled=true", "securedeploy.threat-intelligence.enabled=true"})
@AutoConfigureMockMvc
class ThreatIntelReviewIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @MockBean VulnerabilityDataSource osv;
    @MockBean EpssClient epss;
    @MockBean CisaKevClient kev;
    String token;
    @BeforeEach void setup() throws Exception {
        when(osv.lookup(anyList())).thenAnswer(invocation -> {
            List<DependencyComponent> components = invocation.getArgument(0);
            var c = components.get(0);
            var f = new DependencyVulnerability(c.ecosystem(), c.packageName(), c.version(), "GHSA-fixture", List.of(CVE),
                    "Synthetic advisory", Severity.HIGH, null, List.of(), List.of(), null, null, List.of(), List.of(c.sourceFile()));
            return new VulnerabilityDataSource.LookupResult(List.of(f), Set.of(c.identity()), false, List.of());
        });
        when(epss.lookup(anyList())).thenReturn(Map.of(CVE, epss(.8,.98)));
        when(kev.lookup(anyList())).thenReturn(Map.of(CVE, kev(false,LookupStatus.AVAILABLE)));
        var signup = Map.of("email", "threat-"+UUID.randomUUID()+"@test.invalid", "password", "Fake-fixture-password-1234", "name", "Threat fixture");
        token = mapper.readTree(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsBytes(signup))).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    @Test void snapshotsPersistWithoutRefreshOnDetailAndRescanningUsesNewSignals() throws Exception {
        var first = upload();
        assertThat(first.at("/riskAssessment/dependencyFindings/0/reasonCode").asText()).isEqualTo("HIGH_EXPLOIT_PROBABILITY");
        long review = first.path("reviewId").asLong();
        assertThat(jdbc.queryForObject("select risk_assessment_json from reviews where id=?", String.class, review)).contains("threatIntelligence", "snapshotId", "blockingScore");
        when(epss.lookup(anyList())).thenReturn(Map.of(CVE, epss(.01,.1)));
        clearInvocations(epss, kev);
        var historical = detail(review);
        assertThat(historical.path("riskAssessment")).isEqualTo(first.path("riskAssessment"));
        verifyNoInteractions(epss, kev);
        var second = upload();
        assertThat(second.at("/riskAssessment/threatIntelligence/snapshotId")).isNotEqualTo(first.at("/riskAssessment/threatIntelligence/snapshotId"));
        assertThat(second.at("/riskAssessment/dependencyFindings/0/priority").asText()).isEqualTo("SHOULD_FIX");
        assertThat(second.path("securityScore")).isEqualTo(first.path("securityScore"));
        assertThat(second.path("deploymentStatus")).isEqualTo(first.path("deploymentStatus"));
    }
    @Test void kevWinsOverEpssAndUnavailableEnrichmentStillCommitsReview() throws Exception {
        when(kev.lookup(anyList())).thenReturn(Map.of(CVE, kev(true,LookupStatus.AVAILABLE)));
        var kevResult = upload();
        assertThat(kevResult.at("/riskAssessment/dependencyFindings/0/reasonCode").asText()).isEqualTo("KNOWN_EXPLOITED_VULNERABILITY");
        when(epss.lookup(anyList())).thenThrow(new IllegalStateException("Fixture offline"));
        when(kev.lookup(anyList())).thenThrow(new IllegalStateException("Fixture timeout"));
        var failed = upload();
        assertThat(failed.path("reviewId").asLong()).isPositive();
        assertThat(failed.at("/riskAssessment/dependencyFindings/0/priority").asText()).isEqualTo("SHOULD_FIX");
        assertThat(failed.at("/riskAssessment/prioritizedDeploymentAssessment").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(failed.at("/riskAssessment/assessmentCoverage/sca").asText()).isEqualTo("COMPLETE");
        assertThat(failed.at("/riskAssessment/threatIntelligence/status").asText()).isEqualTo("UNAVAILABLE");
        assertThat(detail(failed.path("reviewId").asLong()).path("riskAssessment")).isEqualTo(failed.path("riskAssessment"));
    }
    @Test void phase3JsonWithoutThreatFieldsRemainsReadableAndDoesNotFetch() throws Exception {
        var result = upload();
        var old = (com.fasterxml.jackson.databind.node.ObjectNode) result.path("riskAssessment");
        old.remove(List.of("threatIntelligence", "threatPolicy"));
        ((com.fasterxml.jackson.databind.node.ObjectNode) old.path("assessmentCoverage")).remove("threatIntelligence");
        old.put("schemaVersion",2).put("policyVersion","risk-v1.1");
        jdbc.update("update reviews set risk_assessment_json=? where id=?", old.toString(), result.path("reviewId").asLong());
        clearInvocations(epss,kev);
        var historical = detail(result.path("reviewId").asLong());
        assertThat(historical.at("/riskAssessment/threatIntelligence").isNull()).isTrue();
        assertThat(historical.at("/riskAssessment/policyVersion").asText()).isEqualTo("risk-v1.1");
        verifyNoInteractions(epss,kev);
    }
    JsonNode detail(long id) throws Exception {
        return mapper.readTree(mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode upload() throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("threat-fixture/package.json"));
            zip.write("{\"dependencies\":{\"threat-fixture\":\"1.0.0\"}}".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return mapper.readTree(mvc.perform(multipart("/api/reviews/upload")
                .file(new MockMultipartFile("file","threat-fixture.zip","application/zip",bytes.toByteArray()))
                .header("Authorization","Bearer "+token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
}
