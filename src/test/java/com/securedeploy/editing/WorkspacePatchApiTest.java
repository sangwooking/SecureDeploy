package com.securedeploy.editing;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.service.*;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.persistence.repository.*;
import com.securedeploy.github.model.GitHubSourceSnapshot;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.rule.model.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties={"securedeploy.ai.provider=TEMPLATE","securedeploy.sca.enabled=false","securedeploy.threat-intelligence.enabled=false"})
@AutoConfigureMockMvc
class WorkspacePatchApiTest {
    @Autowired MockMvc mvc;@Autowired ObjectMapper json;@Autowired UserRepository users;@Autowired ProjectRepository projects;
    @Autowired ReviewRepository reviews;@Autowired AiProperties properties;
    @MockBean EditingSourceService sources;@MockBean AiProviderResolver resolver;
    final AiProvider provider=mock(AiProvider.class);
    String owner,other,workspace,base,file,hash;long reviewId,findingId;
    @BeforeEach void setup()throws Exception{
        String email=UUID.randomUUID()+"@patch.invalid";owner=signup(email);other=signup(UUID.randomUUID()+"@patch.invalid");
        var user=users.findAll().stream().filter(u->u.getEmail().equals(email)).findFirst().orElseThrow();
        var project=new ProjectEntity("patch fixture",ReviewSourceType.GITHUB,"https://github.com/fixture/patch");project.assignUser(user);projects.saveAndFlush(project);
        var review=new ReviewEntity("patch fixture",ReviewSourceType.GITHUB,project.getRepositoryUrl(),1,1,95,"READY_WITH_WARNINGS");review.assignProject(project);
        review.attachSourceMetadata(new GitHubSourceSnapshot("fixture","patch",project.getRepositoryUrl(),"main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(3L,2L,true));
        var finding=new VulnerabilityEntity("DEBUG_ENABLED",RuleCategory.CONFIGURATION,Severity.MEDIUM,"application.properties",1,"debug declaration","Review production config","debug=true");review.addVulnerability(finding);reviews.saveAndFlush(review);
        reviewId=review.getId();findingId=finding.getId();
        when(sources.github(anyLong(),any())).thenAnswer(i->List.of(new SourceArchive.Entry("application.properties","debug=true\n".getBytes(StandardCharsets.UTF_8),false,0100644)));
        properties.setProvider(AiProviderType.OPENAI);when(resolver.resolve()).thenReturn(provider);when(provider.providerType()).thenReturn(AiProviderType.OPENAI);when(provider.isAvailable()).thenReturn(true);when(provider.consumeLastTokenUsage()).thenReturn(Optional.empty());
        when(provider.generateWorkspacePatch(any())).thenAnswer(i->{var data=json.readTree(((WorkspacePatch.Prompt)i.getArgument(0)).untrustedData());return new WorkspacePatch.Output("PATCH",data.path("fileId").asText(),data.path("startLine").asInt(),data.path("expectedHash").asText(),"debug=false","설정 변경 제안입니다.",List.of("로컬 동작 확인과 재검사"),List.of("운영 환경은 미확인입니다."));});
        var created=postJson("/api/editing-workspaces/github/"+reviewId,Map.of(),owner,200);
        workspace=created.path("id").asText();base="/api/editing-workspaces/"+workspace;file=created.at("/files/0/id").asText();hash=created.at("/files/0/originalHash").asText();
    }
    @AfterEach void cleanup()throws Exception{if(base!=null)mvc.perform(delete(base).header("Authorization","Bearer "+owner));}
    String signup(String email)throws Exception{return postJson("/api/auth/signup",Map.of("email",email,"name","patch fixture","password","Synthetic-Only-124!"),null,200).path("accessToken").asText();}
    JsonNode postJson(String path,Object body,String token,int status)throws Exception{
        var request=post(path).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsBytes(body));if(token!=null)request.header("Authorization","Bearer "+token);
        return json.readTree(mvc.perform(request).andExpect(status().is(status)).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode getJson(String path,String token)throws Exception{return json.readTree(mvc.perform(get(path).header("Authorization","Bearer "+token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());}
    JsonNode prepare()throws Exception{var content=getJson(base+"/files/"+file,owner);return postJson(base+"/patches",Map.of("fileId",file,"findingId",findingId,"revision",1,"originalHash",hash,"currentHash",content.path("currentHash").asText()),owner,200);}
    @Test void actualJwtApiConsentProposalApprovalExportIsolationAndReviewImmutability()throws Exception{
        var before=getJson("/api/reviews/"+reviewId,owner);var p=prepare();String path=base+"/patches/"+p.path("id").asText();String current=p.path("currentHash").asText();
        postJson(path+"/generate",Map.of("revision",1,"currentHash",current,"consented",false),owner,409);verify(provider,never()).generateWorkspacePatch(any());
        mvc.perform(get(path).header("Authorization","Bearer "+other)).andExpect(status().isNotFound());
        postJson(path+"/generate",Map.of("revision",1,"currentHash",current,"consented",true),other,404);
        var generated=postJson(path+"/generate",Map.of("revision",1,"currentHash",current,"consented",true),owner,200);assertEquals("PROPOSED",generated.path("state").asText());
        assertEquals("debug=true\n",getJson(base+"/files/"+file,owner).path("text").asText());
        postJson(path+"/apply",Map.of("revision",1,"currentHash",current,"approved",true),other,404);
        postJson(path+"/apply",Map.of("revision",1,"currentHash",current,"approved",false),owner,409);
        var applied=postJson(path+"/apply",Map.of("revision",1,"currentHash",current,"approved",true),owner,200);assertEquals(2,applied.path("revision").asInt());
        postJson(path+"/apply",Map.of("revision",1,"currentHash",current,"approved",true),owner,409);
        byte[] zip=mvc.perform(post(base+"/export/zip").header("Authorization","Bearer "+owner).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsBytes(Map.of("revision",2,"changedFileIds",List.of(file),"approved",true))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray();
        assertEquals("debug=false\n",new String(SourceArchive.read(new java.io.ByteArrayInputStream(zip)).get(0).bytes(),StandardCharsets.UTF_8));
        assertEquals(before,getJson("/api/reviews/"+reviewId,owner));
    }
    @Test void actualApiManualSaveStalesProposalAndDeletionRevokesAccess()throws Exception{
        var p=prepare();String path=base+"/patches/"+p.path("id").asText();String current=p.path("currentHash").asText();
        mvc.perform(put(base+"/files/"+file).header("Authorization","Bearer "+owner).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsBytes(Map.of("revision",1,"originalHash",hash,"text","debug=true\n# manual\n")))).andExpect(status().isOk());
        assertEquals("STALE",getJson(path,owner).path("state").asText());postJson(path+"/generate",Map.of("revision",1,"currentHash",current,"consented",true),owner,409);verify(provider,never()).generateWorkspacePatch(any());
        mvc.perform(delete(base).header("Authorization","Bearer "+owner)).andExpect(status().isOk());mvc.perform(get(path).header("Authorization","Bearer "+owner)).andExpect(status().isNotFound());
    }
}
