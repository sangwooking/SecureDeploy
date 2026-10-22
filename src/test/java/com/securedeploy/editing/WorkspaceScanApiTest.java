package com.securedeploy.editing;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.service.*;
import com.securedeploy.github.model.GitHubSourceSnapshot;
import com.securedeploy.persistence.repository.*;
import com.securedeploy.review.model.ReviewSourceType;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties={"securedeploy.ai.provider=TEMPLATE","securedeploy.sca.enabled=false","securedeploy.threat-intelligence.enabled=false"})
@AutoConfigureMockMvc
class WorkspaceScanApiTest {
    @Autowired MockMvc mvc; @Autowired ObjectMapper json; @Autowired ReviewRepository reviews;
    @Autowired AiProperties properties; @Autowired PlatformTransactionManager transactions;
    @MockBean EditingSourceService sources; @MockBean AiProviderResolver resolver;
    final AiProvider provider=mock(AiProvider.class);
    String owner, other, base, id, file, hash; long originalId; List<SourceArchive.Entry> entries;
    @BeforeEach void setup() throws Exception {
        owner=signup();other=signup();
        entries=List.of(new SourceArchive.Entry("application.properties", "debug=true\nserver.error.include-stacktrace=always\n".getBytes(StandardCharsets.UTF_8),false,0100644),
                new SourceArchive.Entry("unsupported.rs", "// synthetic unsupported code\n".getBytes(StandardCharsets.UTF_8), false,0100644));
        when(sources.github(anyLong(),any())).thenAnswer(i->entries.stream().map(e->new SourceArchive.Entry(e.path(),e.bytes().clone(),e.directory(),e.mode())).toList());
        properties.setProvider(AiProviderType.OPENAI);when(resolver.resolve()).thenReturn(provider);
        when(provider.providerType()).thenReturn(AiProviderType.OPENAI);when(provider.isAvailable()).thenReturn(true);
        when(provider.consumeLastTokenUsage()).thenReturn(Optional.empty());
        when(provider.generateWorkspacePatch(any())).thenAnswer(i->{var d=json.readTree(((WorkspacePatch.Prompt)i.getArgument(0)).untrustedData());return new WorkspacePatch.Output("PATCH",d.path("fileId").asText(),d.path("startLine").asInt(),d.path("expectedHash").asText(),"debug=false","설정 변경 제안",List.of("재검사"),List.of("운영 미확인"));});
    }
    @AfterEach void cleanup()throws Exception {if(base!=null)mvc.perform(delete(base).header("Authorization","Bearer "+owner));}
    String signup()throws Exception{return postJson("/api/auth/signup",Map.of("email",UUID.randomUUID()+"@scan.invalid","name","scan fixture","password","Synthetic-Only-124!"),null,200).path("accessToken").asText();}
    JsonNode postJson(String path,Object body,String token,int status)throws Exception{
        var req=post(path).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsBytes(body));if(token!=null)req.header("Authorization","Bearer "+token);
        return json.readTree(mvc.perform(req).andExpect(status().is(status)).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode getJson(String path,String token)throws Exception{return json.readTree(mvc.perform(get(path).header("Authorization","Bearer "+token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());}
    JsonNode acquire(boolean exact)throws Exception {
        var archive=new MockMultipartFile("file","fixture.zip","application/zip",SourceArchive.zip(entries));
        var result=json.readTree(mvc.perform(multipart("/api/reviews/upload").file(archive).header("Authorization","Bearer "+owner)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        originalId=result.path("reviewId").asLong();
        if(exact)new TransactionTemplate(transactions).execute(s->{var review=reviews.findByIdWithVulnerabilities(originalId).orElseThrow();
            ReflectionTestUtils.setField(review,"sourceType",ReviewSourceType.GITHUB);
            ReflectionTestUtils.setField(review,"repositoryUrl","https://github.com/fixture/scan");
            review.attachSourceMetadata(new GitHubSourceSnapshot("fixture","scan","https://github.com/fixture/scan","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()));return null;});
        JsonNode created;
        if(exact)created=postJson("/api/editing-workspaces/github/"+originalId,Map.of(),owner,200);
        else created=json.readTree(mvc.perform(multipart("/api/editing-workspaces/zip/"+originalId).file(archive).header("Authorization","Bearer "+owner)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        id=created.path("id").asText();base="/api/editing-workspaces/"+id;file=created.at("/files/0/id").asText();hash=created.at("/files/0/originalHash").asText();return created;
    }
    JsonNode save(String text,long revision)throws Exception {
        return json.readTree(mvc.perform(put(base+"/files/"+file).header("Authorization","Bearer "+owner).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(Map.of("revision",revision,"originalHash",hash,"text",text)))).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    Map<String,Object> scanRequest(JsonNode workspace){return Map.of("revision",workspace.path("revision").asLong(),"changedFileIds",json.convertValue(workspace.path("changedFileIds"),List.class),"approved",true,"externalLookupAcknowledged",true);}
    JsonNode scan(JsonNode workspace)throws Exception {
        var job=postJson(base+"/scans",scanRequest(workspace),owner,202);String path="/api/editing-workspaces/scans/"+job.path("id").asText();
        postJson(base+"/scans",scanRequest(workspace),other,404);
        mvc.perform(get(path).header("Authorization","Bearer "+other)).andExpect(status().isNotFound());
        for(int i=0;i<300;i++) {var state=getJson(path,owner);if(!state.path("state").asText().equals("RUNNING")){assertEquals("SUCCEEDED",state.path("state").asText(),state.toString());return getJson("/api/reviews/"+state.path("reviewId").asLong(),owner);}Thread.sleep(30);}
        throw new AssertionError("scan timeout");
    }
    @Test void manualEditExecutesRealEngineAndPersistsComparisonAfterWorkspaceDeletion()throws Exception {
        acquire(true);var before=getJson("/api/reviews/"+originalId,owner);
        var current=save("debug=false\nserver.error.include-stacktrace=always\nserver.servlet.session.cookie.secure=false\n",1);
        var result=scan(current);
        assertEquals("WORKSPACE",result.path("sourceType").asText());assertTrue(result.path("sourceMetadata").isNull());
        assertEquals(originalId,result.at("/comparison/baselineReviewId").asLong());
        assertEquals(2,result.at("/workspaceScan/revision").asInt());assertEquals("a".repeat(40),result.at("/workspaceScan/sourceRevision").asText());
        assertEquals("MANUAL",result.at("/workspaceScan/files/0/changeOrigin").asText());
        var changes=result.at("/comparison/findings");
        assertTrue(java.util.stream.StreamSupport.stream(changes.spliterator(),false).anyMatch(n->n.path("status").asText().equals("RESOLVED")&&n.at("/before/risk/ruleId").asText().equals("DEBUG_ENABLED")));
        assertTrue(java.util.stream.StreamSupport.stream(changes.spliterator(),false).anyMatch(n->n.path("status").asText().equals("REMAINING")));
        assertTrue(java.util.stream.StreamSupport.stream(changes.spliterator(),false).anyMatch(n->n.path("status").asText().equals("NEW")));
        assertEquals(before,getJson("/api/reviews/"+originalId,owner));
        mvc.perform(delete(base).header("Authorization","Bearer "+owner)).andExpect(status().isOk());
        assertEquals(result,getJson("/api/reviews/"+result.path("reviewId").asLong(),owner));
        mvc.perform(get("/api/reviews/"+result.path("reviewId").asLong()).header("Authorization","Bearer "+other)).andExpect(status().isForbidden());
        verify(provider,never()).generateWorkspacePatch(any());
    }
    @Test void approvedAiPatchIsActuallyAnalyzedAndRaisesOnlyReferenceScoreWithPartialCoverage()throws Exception {
        acquire(true);var before=getJson("/api/reviews/"+originalId,owner);
        long finding=java.util.stream.StreamSupport.stream(before.path("vulnerabilities").spliterator(),false).filter(n->n.path("ruleId").asText().equals("DEBUG_ENABLED")).findFirst().orElseThrow().path("vulnerabilityId").asLong();
        var content=getJson(base+"/files/"+file,owner);var proposal=postJson(base+"/patches",Map.of("fileId",file,"findingId",finding,"revision",1,"originalHash",hash,"currentHash",content.path("currentHash").asText()),owner,200);
        String p=base+"/patches/"+proposal.path("id").asText();String current=proposal.path("currentHash").asText();
        postJson(p+"/generate",Map.of("revision",1,"currentHash",current,"consented",true),owner,200);
        var applied=postJson(p+"/apply",Map.of("revision",1,"currentHash",current,"approved",true),owner,200);
        var result=scan(applied);assertEquals("AI_APPROVED",result.at("/workspaceScan/files/0/changeOrigin").asText());
        assertTrue(result.path("securityScore").asInt()>before.path("securityScore").asInt());assertEquals("PARTIAL",result.at("/coverage/status").asText());
        assertFalse(java.util.stream.StreamSupport.stream(result.path("vulnerabilities").spliterator(),false).anyMatch(n->n.path("ruleId").asText().equals("DEBUG_ENABLED")));
        assertEquals("risk-v1.2",result.at("/riskAssessment/policyVersion").asText());
        byte[] zip=mvc.perform(post(base+"/export/zip").header("Authorization","Bearer "+owner).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsBytes(Map.of("revision",2,"changedFileIds",List.of(file),"approved",true))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray();
        var exported=SourceArchive.read(new java.io.ByteArrayInputStream(zip));
        assertEquals(result.at("/workspaceScan/files/0/currentHash").asText(),SourceArchive.hash(exported.get(0).bytes()));
        assertEquals(before,getJson("/api/reviews/"+originalId,owner));
    }
    @Test void zipReuploadIsNewProjectBaselineWithoutFalseResolved()throws Exception {
        acquire(false);var before=getJson("/api/reviews/"+originalId,owner);var changed=save("debug=false\n",1);var result=scan(changed);
        assertNotEquals(before.path("projectId").asLong(),result.path("projectId").asLong());
        assertEquals("NO_BASELINE",result.at("/comparison/status").asText());assertTrue(result.at("/comparison/baselineReviewId").isNull());
        assertEquals(0,result.at("/comparison/counts/RESOLVED").asInt());assertFalse(result.at("/workspaceScan/baselineVerified").asBoolean());
        assertEquals(originalId,result.at("/workspaceScan/originalReviewId").asLong());assertEquals(before,getJson("/api/reviews/"+originalId,owner));
    }
    @Test void analyzerVersionMismatchNeverResolvesOldWarnings() throws Exception {
        var created=acquire(true);
        new TransactionTemplate(transactions).execute(s->{var r=reviews.findByIdWithVulnerabilities(originalId).orElseThrow();var c=r.getComparisonContext();
            r.attachComparisonContext(new com.securedeploy.project.progress.ComparisonContext(c.schemaVersion(),c.baselineReviewId(),"synthetic-previous-version",c.ruleAnalysisComplete(),c.analyzedFiles()));return null;});
        var result=scan(save("debug=false\n",created.path("revision").asLong()));
        assertEquals(0,result.at("/comparison/counts/RESOLVED").asInt());assertTrue(result.at("/comparison/counts/UNAVAILABLE").asInt()>0);
        assertEquals("NOT_COMPARED",result.at("/resultSummary/structuralComparison").asText());
    }
    @Test void wrappedZipReusesUploadRootSelectionWhileKeepingArchiveHashPaths() throws Exception {
        entries=List.of(new SourceArchive.Entry("bundle/application.properties","debug=true\n".getBytes(StandardCharsets.UTF_8),false,0100644));
        acquire(false);var current=save("debug=false\n",1);var result=scan(current);
        assertEquals("bundle",result.at("/workspaceScan/analysisRoot").asText());
        assertEquals("bundle/application.properties",result.at("/workspaceScan/files/0/path").asText());
        assertEquals(0,result.path("vulnerabilityCount").asInt());assertEquals("NO_BASELINE",result.at("/comparison/status").asText());
    }
    @Test void generatedButUnapprovedPatchNeverEntersScanAndDuplicateDoesNotCreateReview() throws Exception {
        var created=acquire(true);var before=getJson("/api/reviews/"+originalId,owner);
        long finding=java.util.stream.StreamSupport.stream(before.path("vulnerabilities").spliterator(),false).filter(n->n.path("ruleId").asText().equals("DEBUG_ENABLED")).findFirst().orElseThrow().path("vulnerabilityId").asLong();
        var content=getJson(base+"/files/"+file,owner);var p=postJson(base+"/patches",Map.of("fileId",file,"findingId",finding,"revision",1,"originalHash",hash,"currentHash",content.path("currentHash").asText()),owner,200);
        String path=base+"/patches/"+p.path("id").asText();
        postJson(path+"/generate",Map.of("revision",1,"currentHash",p.path("currentHash").asText(),"consented",true),owner,200);
        var result=scan(created);assertTrue(java.util.stream.StreamSupport.stream(result.path("vulnerabilities").spliterator(),false).anyMatch(n->n.path("ruleId").asText().equals("DEBUG_ENABLED")));
        assertFalse(result.at("/workspaceScan/files/0/changed").asBoolean());assertEquals("UNCHANGED",result.at("/workspaceScan/files/0/changeOrigin").asText());
        postJson(path+"/reject",Map.of(),owner,200);
        var duplicate=postJson(base+"/scans",scanRequest(created),owner,202);assertEquals(result.path("reviewId").asLong(),duplicate.path("reviewId").asLong());
    }
}
