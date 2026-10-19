package com.securedeploy.analysis.python;

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
class PythonAnalysisIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired jakarta.persistence.EntityManager entities;
    @MockBean GitHubRepositoryService github;
    @MockBean PrivateGitHubSourceService connected;
    @TempDir Path temp;

    @Test void zipPublicAndPrivateShareEvidencePersistenceAndCleanupWithoutChangingRisk() throws Exception {
        String token = signup();
        var zip = upload(token, PythonServerAnalyzerTest.UNSAFE);
        var safe = upload(token, PythonServerAnalyzerTest.SAFE);
        assertThat(zip.at("/serverAnalysis/pythonAnalysis/findings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/pythonAnalysis/validatedFindings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/pythonAnalysis/validatedFindings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(zip.at("/serverAnalysis/pythonAnalysis/validatedFindings/0/comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        assertThat(zip.at("/serverAnalysis/pythonAnalysis/validatedFindings/0/executionLocations")).isNotEmpty();
        assertThat(safe.at("/serverAnalysis/pythonAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.at("/serverAnalysis/pythonAnalysis/findings")).isEmpty();
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
                .contains("PY_SQL_INPUT_FLOW", "py-flow:", "verificationSteps").doesNotContain("SELECT *");
        mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + signup())).andExpect(status().isForbidden());
        mvc.perform(get("/api/reviews").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews/" + id + "/report").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/reviews/" + id + "/ai-summary").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        jdbc.update("update reviews set server_analysis_json=null where id=?", id); entities.clear();
        assertThat(detail(token, id).path("serverAnalysis").isNull()).isTrue();
        assertThat(detail(token, id).path("riskAssessment")).isEqualTo(zip.path("riskAssessment"));
    }
    @Test void syntaxFailureIsStoredAsIncompleteWithoutInventingFindings() throws Exception {
        String token = signup(); var result = upload(token, "def bad(\n");
        assertThat(result.at("/serverAnalysis/pythonAnalysis/status").asText()).isEqualTo("PARTIAL");
        assertThat(result.at("/serverAnalysis/pythonAnalysis/files/0/parseStatus").asText()).isEqualTo("PARSE_FAILED");
        assertThat(result.at("/serverAnalysis/pythonAnalysis/findings")).isEmpty();
        assertThat(result.path("coverage").path("analyzers").toString()).contains("PYTHON_SERVER", "AST_PARSE_FAILED");
        assertThat(detail(token, result.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(result.path("serverAnalysis"));
    }
    @Test void resourceEvidenceSharesTransportPersistenceAndOwnershipWithoutRiskPromotion() throws Exception {
        String code = "import pickle\nfrom rest_framework.decorators import api_view\n@api_view(['POST'])\ndef endpoint(request):\n open(request.GET['path'])\n return pickle.loads(request.body)\n";
        String token = signup(); var zip = upload(token, code);
        var safe = upload(token, code.replace("open(request.GET['path'])", "open('/fixed')").replace("import pickle", "import json").replace("pickle.loads", "json.loads"));
        var snapshot = zip.at("/serverAnalysis/pythonAnalysis");
        assertThat(snapshot.path("resourceUses")).hasSize(2);
        assertThat(snapshot.path("validatedFindings")).hasSize(2);
        for (var finding : snapshot.path("validatedFindings")) {
            assertThat(finding.path("priority").asText()).isEqualTo("REVIEW_REQUIRED");
            assertThat(finding.path("comparisonPolicy").asText()).isEqualTo("NOT_COMPARED");
        }
        assertThat(safe.at("/serverAnalysis/pythonAnalysis/validatedFindings")).isEmpty();
        for (String key : List.of("securityScore", "vulnerabilityCount", "deploymentStatus")) assertThat(zip.path(key)).isEqualTo(safe.path(key));
        for (String key : List.of("prioritySummary", "prioritizedDeploymentAssessment")) assertThat(zip.path("riskAssessment").path(key)).isEqualTo(safe.path("riskAssessment").path(key));
        Path publicRoot=source("resource-public",code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture", "https://github.com/fixture/files", publicRoot, publicRoot));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/files\",\"scanMode\":\"STANDARD\"}");
        Path privateRoot=source("resource-private",code);
        var metadata=new GitHubSourceSnapshot("fixture","files","https://github.com/fixture/files","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/files",privateRoot,privateRoot,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(snapshot);
        assertThat(privateResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(snapshot);
        assertThat(publicRoot).doesNotExist(); assertThat(privateRoot).doesNotExist();
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).at("/serverAnalysis/pythonAnalysis")).isEqualTo(snapshot);
        assertThat(zip.at("/coverage/analyzers").toString()).contains("RESOURCE_INPUT_IN_FILE_PATH", "RESOURCE_INPUT_TO_UNSAFE_DESERIALIZATION");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
        assertThat(zip.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
    }
    @Test void tokenEvidenceUsesCommonSourcesAndPreservesRiskAndIsolation() throws Exception {
        String code=PythonTokenFindingTest.SOURCE;
        String token=signup();var zip=upload(token,code);
        var checked=upload(token,code.replace("'verify_signature':False","'verify_signature':True"));
        var evidence=zip.at("/serverAnalysis/pythonAnalysis");
        assertThat(evidence.path("tokenUses")).hasSize(1);
        assertThat(evidence.path("validatedFindings")).hasSize(1);
        assertThat(checked.at("/serverAnalysis/pythonAnalysis/validatedFindings")).isEmpty();
        for(String key:List.of("securityScore","vulnerabilityCount","deploymentStatus"))assertThat(zip.path(key)).isEqualTo(checked.path(key));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment"))assertThat(zip.path("riskAssessment").path(key)).isEqualTo(checked.path("riskAssessment").path(key));
        Path pub=source("token-public",code),prv=source("token-private",code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/tokens",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/tokens\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","tokens","https://github.com/fixture/tokens","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/tokens",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(privateResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(zip.at("/coverage/analyzers").toString()).contains("PYTHON_TOKEN_SECURITY");
        assertThat(zip.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }
    @Test void exposureEvidencePersistsAcrossSourcesWithoutRiskPromotion() throws Exception {
        String code=ExposureFindingTest.PYTHON;
        String token=signup();var zip=upload(token,code);var normal=upload(token,code.replace("settings.SECRET_KEY","'public'"));
        var evidence=zip.at("/serverAnalysis/pythonAnalysis");
        assertThat(evidence.path("exposureUses")).hasSize(1);assertThat(evidence.path("validatedFindings")).hasSize(1);
        assertThat(normal.at("/serverAnalysis/pythonAnalysis/validatedFindings")).isEmpty();
        for(String key:List.of("securityScore","vulnerabilityCount","deploymentStatus"))assertThat(zip.path(key)).isEqualTo(normal.path(key));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment"))assertThat(zip.path("riskAssessment").path(key)).isEqualTo(normal.path("riskAssessment").path(key));
        Path pub=source("exposure-public",code),prv=source("exposure-private",code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/exposure",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/exposure\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","exposure","https://github.com/fixture/exposure","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/exposure",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);assertThat(privateResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        long id=zip.path("reviewId").asLong();assertThat(detail(token,id).at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(zip.at("/coverage/analyzers").toString()).contains("PYTHON_EXPOSURE");
        assertThat(zip.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }
    @Test void serviceAndErrorUseCommonSourcesWithoutChangingRiskOrHistory() throws Exception {
        String code=ServiceSecurityFindingTest.SOURCE,token=signup();
        var zip=upload(token,code);var normal=upload(token,code.replace("timeout=None","timeout=3").replace("traceback.format_stack()","'generic error'"));
        var evidence=zip.at("/serverAnalysis/pythonAnalysis");assertThat(evidence.path("validatedFindings")).hasSize(2);
        assertThat(normal.at("/serverAnalysis/pythonAnalysis/validatedFindings")).isEmpty();
        for(String key:List.of("securityScore","vulnerabilityCount","deploymentStatus"))assertThat(zip.path(key)).isEqualTo(normal.path(key));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment"))assertThat(zip.path("riskAssessment").path(key)).isEqualTo(normal.path("riskAssessment").path(key));
        Path pub=source("service-public",code),prv=source("service-private",code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/service",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/service\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","service","https://github.com/fixture/service","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/service",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);assertThat(privateResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(zip.at("/coverage/analyzers").toString()).contains("PYTHON_SERVICE_STABILITY");
        assertThat(zip.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }
    Path source(String dir, String code) throws Exception {
        Path root=Files.createDirectory(temp.resolve(dir)); Files.writeString(root.resolve("views.py"),code);return root;
    }
    @Test void authorizationDetailsPersistAcrossAllSourcesWithoutChangingRiskOrOtherUserAccess() throws Exception {
        String code=PythonAuthorizationFindingTest.UNSAFE;
        String token=signup();var zip=upload(token,code);var safe=upload(token,PythonAuthorizationFindingTest.SAFE);
        var evidence=zip.at("/serverAnalysis/pythonAnalysis");
        assertThat(evidence.path("validatedFindings")).hasSize(1);
        assertThat(evidence.at("/authorizationContexts/0/details/permissionSource").asText()).isEqualTo("VIEW_DECORATOR");
        assertThat(evidence.at("/authorizationContexts/0/details/objectAuthorizationStatus").asText()).isEqualTo("RISK_LOGIC_CANDIDATE");
        assertThat(safe.at("/serverAnalysis/pythonAnalysis/validatedFindings")).isEmpty();
        for(String key:List.of("securityScore","vulnerabilityCount","deploymentStatus"))assertThat(zip.path(key)).isEqualTo(safe.path(key));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment"))assertThat(zip.path("riskAssessment").path(key)).isEqualTo(safe.path("riskAssessment").path(key));
        Path pub=source("auth-public",code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/auth",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/auth\",\"scanMode\":\"STANDARD\"}");
        Path prv=source("auth-private",code);
        var metadata=new GitHubSourceSnapshot("fixture","auth","https://github.com/fixture/auth","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/auth",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(privateResult.at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).at("/serverAnalysis/pythonAnalysis")).isEqualTo(evidence);
        assertThat(zip.at("/coverage/analyzers").toString()).contains("PYTHON_AUTHORIZATION");
        assertThat(zip.at("/semanticReview/semanticReviewStatus").asText()).isEqualTo("NOT_REQUESTED");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }
    Path source(String dir) throws Exception {
        Path root = Files.createDirectory(temp.resolve(dir)); Files.writeString(root.resolve("views.py"), PythonServerAnalyzerTest.UNSAFE); return root;
    }
    String signup() throws Exception { return postJson("/api/auth/signup", null, json.writeValueAsString(Map.of(
            "email", UUID.randomUUID() + "@py-fixture.invalid", "password", UUID.randomUUID().toString(), "name", "AST fixture"))).path("accessToken").asText(); }
    JsonNode postJson(String path, String token, String body) throws Exception {
        var request = post(path).contentType(MediaType.APPLICATION_JSON).content(body);
        if (token != null) request.header("Authorization", "Bearer " + token);
        return json.readTree(mvc.perform(request).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode detail(String token, long id) throws Exception { return json.readTree(mvc.perform(get("/api/reviews/" + id).header("Authorization", "Bearer " + token))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()); }
    JsonNode upload(String token, String code) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) { zip.putNextEntry(new ZipEntry("fixture/views.py")); zip.write(code.getBytes(StandardCharsets.UTF_8)); zip.closeEntry(); }
        return json.readTree(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file", "fixture.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
}
