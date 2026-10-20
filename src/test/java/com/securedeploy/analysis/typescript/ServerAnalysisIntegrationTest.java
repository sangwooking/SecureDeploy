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

    @Test void semanticStringReconciliationPersistsAndPublicGithubMatchesZip() throws Exception {
        String token=signup();
        String code="const icon=<svg xmlns=\"http://www.w3.org/2000/svg\"/>;\n"
                +"button.innerText=hidden?'Show Secret':'Hide Secret';\n"
                +"fetch('http://service.example.invalid');";
        var zip=uploadSource(token,"Controls.tsx",code);
        assertThat(zip.path("vulnerabilities")).hasSize(1);
        assertThat(zip.at("/vulnerabilities/0/ruleId").asText()).isEqualTo("INSECURE_API_URL");
        assertThat(zip.at("/vulnerabilities/0/confidence").asText()).isEqualTo("HIGH");
        Path root=Files.createDirectory(temp.resolve("string-public"));Files.writeString(root.resolve("Controls.tsx"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/strings",root,root));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/strings\",\"scanMode\":\"STANDARD\"}");
        assertThat(pub.path("vulnerabilityCount")).isEqualTo(zip.path("vulnerabilityCount"));
        assertThat(pub.path("securityScore")).isEqualTo(zip.path("securityScore"));
        assertThat(pub.at("/riskAssessment/prioritySummary")).isEqualTo(zip.at("/riskAssessment/prioritySummary"));
        assertThat(detail(token,zip.path("reviewId").asLong()).path("vulnerabilities")).isEqualTo(zip.path("vulnerabilities"));
        assertThat(root).doesNotExist();
    }

    @Test void eightyJavaUnitsAndSourceLimitHavePersistedDistinctCoverage() throws Exception {
        String token=signup();var sources=new LinkedHashMap<String,String>();
        sources.put("Endpoint.java","import org.springframework.web.bind.annotation.*; import java.sql.Connection; @RestController class Endpoint { Connection c; @GetMapping(\"/\") void inspect(@RequestParam String input){c.prepareCall(\"{call \"+input+\"}\").execute();}}");
        for(int i=0;i<79;i++)sources.put("types/Record"+i+".java","class Record"+i+" {String copy(String value){return value;}}");
        var zip=uploadSources(token,sources);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/analysis/files")).hasSize(80);
        for(var file:zip.at("/serverAnalysis/javaAnalysis/analysis/files"))assertThat(file.path("parseStatus").asText()).isEqualTo("PARSED");
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(detail(token,zip.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        var limited=uploadSource(token,"Huge.java","x".repeat(100_001));
        assertThat(limited.at("/serverAnalysis/javaAnalysis/analysis/status").asText()).isEqualTo("UNAVAILABLE");
        assertThat(limited.at("/serverAnalysis/javaAnalysis/analysis/files/0/parseStatus").asText()).isEqualTo("LIMIT_EXCEEDED");
        assertThat(detail(token,limited.path("reviewId").asLong()).path("coverage")).isEqualTo(limited.path("coverage"));
        assertThat(limited.path("coverage").toString()).contains("SOURCE_SELECTION_LIMIT");
    }

    @Test void javaSqlUsesCommonInputsAndStoresIndependentReviewCandidates() throws Exception {
        String token=signup();
        String prefix="import org.springframework.web.bind.annotation.*; import java.sql.Connection; @RestController class Endpoint {Connection connection; @GetMapping(\"/\") void inspect(@RequestParam String input){\n";
        String code=prefix+"connection.prepareCall(\"{call \"+input+\"}\").execute();\n}}";
        var zip=uploadSource(token,"Endpoint.java",code);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings")).hasSize(1);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(zip.path("vulnerabilityCount").asInt()).isZero();assertThat(zip.path("securityScore").asInt()).isEqualTo(100);
        assertThat(zip.at("/riskAssessment/prioritySummary/BLOCKING").asInt()).isZero();
        assertThat(zip.at("/coverage/analyzers").toString()).contains("JAVA_SQL_FLOW");
        Path pub=Files.createDirectory(temp.resolve("java-public")),prv=Files.createDirectory(temp.resolve("java-private"));
        Files.writeString(pub.resolve("Endpoint.java"),code);Files.writeString(prv.resolve("Endpoint.java"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/java",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/java\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","java","https://github.com/fixture/java","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/java",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(privateResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        var normal=uploadSource(token,"Endpoint.java",prefix+"var s=connection.createStatement(); s.executeQuery(\"SELECT 1\");\n}}");
        assertThat(normal.at("/serverAnalysis/javaAnalysis/findings")).isEmpty();
        assertThat(normal.at("/comparison/counts/RESOLVED").asInt()).isZero();
        assertThat(normal.path("riskAssessment").path("prioritySummary")).isEqualTo(zip.path("riskAssessment").path("prioritySummary"));
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(jdbc.queryForObject("select server_analysis_json from reviews where id=?",String.class,id)).contains(com.securedeploy.analysis.javaflow.JavaSqlWorker.VERSION,"JAVA_SQL_INPUT_FLOW").doesNotContain("{call ");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
        var legacy=(com.fasterxml.jackson.databind.node.ObjectNode)zip.path("serverAnalysis").deepCopy();legacy.remove("javaAnalysis");
        jdbc.update("update reviews set server_analysis_json=? where id=?",json.writeValueAsString(legacy),id);entities.clear();
        assertThat(detail(token,id).at("/serverAnalysis/javaAnalysis").isNull()).isTrue();
    }

    @Test void mapperDeclarationsUseCommonInputsAndPersistWithoutSqlSource() throws Exception {
        String token=signup();var sources=new LinkedHashMap<String,String>();
        sources.put("Endpoint.java","package sample; import org.springframework.web.bind.annotation.*; @RestController class Endpoint {@org.springframework.beans.factory.annotation.Autowired Mapper mapper; @GetMapping(\"/\") void inspect(@RequestParam String input){mapper.lookup(input);}}");
        sources.put("Mapper.java","package sample; interface Mapper {String lookup(@org.apache.ibatis.annotations.Param(\"value\") String value);}");
        sources.put("queries.xml","<mapper namespace=\"sample.Mapper\"><select id=\"lookup\">SELECT * FROM test_items WHERE name=${value}</select></mapper>");
        var zip=uploadSources(token,sources);
        assertThat(zip.at("/serverAnalysis/javaAnalysis/analysis/dataAccess").toString()).contains("INPUT_SUBSTITUTION","queries.xml");
        assertThat(zip.at("/serverAnalysis/javaAnalysis/findings")).hasSize(1);
        var roots=new ArrayList<Path>();
        for(String name:List.of("mapper-public","mapper-private")) {
            Path root=Files.createDirectory(temp.resolve(name));roots.add(root);
            for(var entry:sources.entrySet())Files.writeString(root.resolve(entry.getKey()),entry.getValue());
        }
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/mapper",roots.get(0),roots.get(0)));
        var pub=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/mapper\",\"scanMode\":\"STANDARD\"}");
        var meta=new GitHubSourceSnapshot("fixture","mapper","https://github.com/fixture/mapper","main","a".repeat(40),"aaaaaaa",null,null,null,null,3,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/mapper",roots.get(1),roots.get(1),meta));
        var prv=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var value:List.of(pub,prv))assertThat(value.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        for(var root:roots)assertThat(root).doesNotExist();
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(jdbc.queryForObject("select server_analysis_json from reviews where id=?",String.class,id)).contains("dataAccess","INPUT_SUBSTITUTION").doesNotContain("SELECT * FROM test_items");
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void expressCommonInputsStoreReviewOnlyCandidatesAndPreserveHistoricalRisk() throws Exception {
        String token=signup();String code="const express=require('express');const app=express();app.post('/run',(req,res)=>{eval(req.body.code);});";
        var zip=uploadSource(token,"server.cjs",code);
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("JS_EVAL_INPUT_FLOW");
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/priority").asText()).isEqualTo("REVIEW_REQUIRED");
        assertThat(zip.at("/serverAnalysis/nodeUses/0/kind").asText()).isEqualTo("INPUT_TO_EXECUTION");
        assertThat(zip.path("securityScore").asInt()).isEqualTo(100);
        assertThat(zip.at("/riskAssessment/prioritySummary/BLOCKING").asInt()).isZero();
        Path pub=Files.createDirectory(temp.resolve("express-public")),prv=Files.createDirectory(temp.resolve("express-private"));
        Files.writeString(pub.resolve("server.cjs"),code);Files.writeString(prv.resolve("server.cjs"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/express",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/express\",\"scanMode\":\"STANDARD\"}");
        var meta=new GitHubSourceSnapshot("fixture","express","https://github.com/fixture/express","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/express",prv,prv,meta));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        for(var value:List.of(publicResult,privateResult))assertThat(value.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        var fixed=uploadSource(token,"server.cjs",code.replace("eval(req.body.code)","Number(req.body.code)"));
        assertThat(fixed.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(fixed.at("/comparison/counts/RESOLVED").asInt()).isZero();
        assertThat(fixed.path("riskAssessment").path("prioritySummary")).isEqualTo(zip.path("riskAssessment").path("prioritySummary"));
        long id=zip.path("reviewId").asLong();assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
        var stored=(com.fasterxml.jackson.databind.node.ObjectNode)zip.path("serverAnalysis").deepCopy();stored.remove("nodeUses");
        stored.put("analyzerVersion","ts-server-v6");jdbc.update("update reviews set server_analysis_json=? where id=?",json.writeValueAsString(stored),id);entities.clear();
        assertThat(detail(token,id).at("/serverAnalysis/nodeUses").isNull()).isTrue();
        assertThat(detail(token,id).at("/serverAnalysis/analyzerVersion").asText()).isEqualTo("ts-server-v6");
    }

    @Test void ssrfUsesCommonSourcesAndSnapshotWithoutChangingRiskOrComparison() throws Exception {
        String token=signup();
        String code="export default {fetch(request){return fetch(new Request(new URL(request.url).searchParams.get('target')));}}";
        var zip=upload(token,code);
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("TS_SSRF_INPUT_FLOW");
        assertThat(zip.at("/serverAnalysis/httpUses/0/kind").asText()).isEqualTo("INPUT_IN_DESTINATION");
        Path publicRoot=Files.createDirectory(temp.resolve("ssrf-public")); Files.writeString(publicRoot.resolve("worker.ts"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/server",publicRoot,publicRoot));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/server\",\"scanMode\":\"STANDARD\"}");
        Path privateRoot=Files.createDirectory(temp.resolve("ssrf-private")); Files.writeString(privateRoot.resolve("worker.ts"),code);
        var metadata=new GitHubSourceSnapshot("fixture","server","https://github.com/fixture/server","main","a".repeat(40),"aaaaaaa",
                null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/server",privateRoot,privateRoot,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(privateResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(publicRoot).doesNotExist(); assertThat(privateRoot).doesNotExist();
        var safe=upload(token,"export default {fetch(request){return fetch('https://example.invalid/?q='+new URL(request.url).searchParams.get('target'));}}");
        assertThat(safe.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(safe.path("securityScore")).isEqualTo(zip.path("securityScore"));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment","codeFindings"))
            assertThat(safe.path("riskAssessment").path(key)).isEqualTo(zip.path("riskAssessment").path(key));
        assertThat(safe.at("/comparison/counts/RESOLVED").asInt()).isZero();
        long id=zip.path("reviewId").asLong();
        assertThat(detail(token,id).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        mvc.perform(get("/api/reviews/"+id).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void exposureUsesCommonInputSourcesWithoutChangingRiskOrResolvedCounts() throws Exception {
        String token=signup(),code="export default {fetch(request){return Response.json({value:request.headers.get('Authorization')});}}";
        var zip=upload(token,code);var normal=upload(token,code.replace("Authorization","X-Request-ID"));
        assertThat(zip.at("/serverAnalysis/validatedFindings/0/ruleId").asText()).isEqualTo("TS_SENSITIVE_DATA_EXPOSURE");
        assertThat(zip.at("/serverAnalysis/exposureUses")).hasSize(1);
        Path pub=Files.createDirectory(temp.resolve("exposure-public")),prv=Files.createDirectory(temp.resolve("exposure-private"));
        Files.writeString(pub.resolve("worker.ts"),code);Files.writeString(prv.resolve("worker.ts"),code);
        when(github.clonePublicRepository(anyString())).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/exposure",pub,pub));
        var publicResult=postJson("/api/reviews/github",token,"{\"repositoryUrl\":\"https://github.com/fixture/exposure\",\"scanMode\":\"STANDARD\"}");
        var metadata=new GitHubSourceSnapshot("fixture","exposure","https://github.com/fixture/exposure","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(123L,456L,true);
        when(connected.collect(anyLong(),eq(456L),eq(123L))).thenReturn(new ClonedRepository("fixture","https://github.com/fixture/exposure",prv,prv,metadata));
        var privateResult=postJson("/api/reviews/github/connected",token,"{\"repositoryId\":123,\"installationId\":456,\"scanMode\":\"STANDARD\"}");
        assertThat(publicResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));assertThat(privateResult.path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(pub).doesNotExist();assertThat(prv).doesNotExist();
        assertThat(normal.at("/serverAnalysis/validatedFindings")).isEmpty();assertThat(normal.at("/comparison/counts/RESOLVED").asInt()).isZero();
        for(String key:List.of("securityScore","vulnerabilityCount","deploymentStatus"))assertThat(zip.path(key)).isEqualTo(normal.path(key));
        for(String key:List.of("prioritySummary","prioritizedDeploymentAssessment"))assertThat(zip.path("riskAssessment").path(key)).isEqualTo(normal.path("riskAssessment").path(key));
        assertThat(detail(token,zip.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(zip.path("serverAnalysis"));
        assertThat(zip.at("/coverage/analyzers").toString()).contains("TYPESCRIPT_EXPOSURE");
        mvc.perform(get("/api/reviews/"+zip.path("reviewId").asLong()).header("Authorization","Bearer "+signup())).andExpect(status().isForbidden());
    }

    @Test void correctedStatePersistsWithoutChangingRiskOrCountingAFalselyResolvedIssue() throws Exception {
        String token = signup();
        String start = "export default { fetch(request,env) { let id=new URL(request.url).searchParams.get('id'); ";
        var before = upload(token, start + "return env.DB.prepare(id + (id='0')).all(); }}");
        var after = upload(token, start + "return env.DB.prepare((id='0') + id).all(); }}");
        assertThat(before.at("/serverAnalysis/validatedFindings")).hasSize(1);
        assertThat(after.at("/serverAnalysis/validatedFindings")).isEmpty();
        assertThat(after.at("/comparison/counts/RESOLVED").isIntegralNumber()).isTrue();
        assertThat(after.at("/comparison/counts/RESOLVED").asInt()).isZero();
        assertThat(after.path("securityScore")).isEqualTo(before.path("securityScore"));
        assertThat(after.at("/riskAssessment/prioritySummary")).isEqualTo(before.at("/riskAssessment/prioritySummary"));
        assertThat(after.at("/riskAssessment/prioritizedDeploymentAssessment")).isEqualTo(before.at("/riskAssessment/prioritizedDeploymentAssessment"));
        assertThat(detail(token, before.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(before.path("serverAnalysis"));
        assertThat(detail(token, after.path("reviewId").asLong()).path("serverAnalysis")).isEqualTo(after.path("serverAnalysis"));
    }

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
        return uploadSource(token,"worker.ts",code);
    }
    JsonNode uploadSource(String token,String name,String code) throws Exception {
        return uploadSources(token,Map.of(name,code));
    }
    JsonNode uploadSources(String token,Map<String,String> sources) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for(var entry:sources.entrySet()) {zip.putNextEntry(new ZipEntry("fixture/"+entry.getKey()));zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));zip.closeEntry();}
        }
        return json.readTree(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file", "fixture.zip", "application/zip", bytes.toByteArray()))
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
}
