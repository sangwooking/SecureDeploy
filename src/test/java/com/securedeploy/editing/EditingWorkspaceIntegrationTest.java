package com.securedeploy.editing;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.persistence.repository.*;
import com.securedeploy.github.model.GitHubSourceSnapshot;
import com.securedeploy.review.model.ReviewSourceType;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"securedeploy.ai.provider=TEMPLATE", "securedeploy.sca.enabled=false", "securedeploy.threat-intelligence.enabled=false"})
@AutoConfigureMockMvc
class EditingWorkspaceIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired ReviewRepository reviews;
    @Autowired ProjectRepository projects;
    @Autowired UserRepository users;
    @Autowired EditingWorkspaceService service;
    @MockBean EditingSourceService sources;
    String owner, other;
    long reviewId;
    @BeforeEach void setup() throws Exception {
        owner = signup(); String ownerEmail = email; other = signup();
        var user = users.findAll().stream().filter(u -> u.getEmail().equals(ownerEmail)).findFirst().orElseThrow();
        var project = new ProjectEntity("editor", ReviewSourceType.ZIP, null); project.assignUser(user); projects.saveAndFlush(project);
        var review = new ReviewEntity("editor", ReviewSourceType.ZIP, null, 1, 0, 100,"READY"); review.assignProject(project); reviews.saveAndFlush(review); reviewId=review.getId();
    }
    String email;
    String signup() throws Exception {
        email = UUID.randomUUID()+"@editing.invalid";
        return json.readTree(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsBytes(Map.of("email",email,"name","fixture","password","Synthetic-Only-134!"))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    JsonNode create() throws Exception {
        var archive = SourceArchive.zip(List.of(new SourceArchive.Entry("index.ts", "original\n".getBytes(StandardCharsets.UTF_8), false,0100644)));
        return json.readTree(mvc.perform(multipart("/api/editing-workspaces/zip/"+reviewId).file(new MockMultipartFile("file","original.zip","application/zip",archive)).header("Authorization","Bearer "+owner))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control","no-store")).andReturn().getResponse().getContentAsByteArray());
    }
    @Test void actualApiOwnerIsolationStaleSaveApprovalExportAndImmutableReview() throws Exception {
        var before = mvc.perform(get("/api/reviews/"+reviewId).header("Authorization","Bearer "+owner)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray();
        var workspace=create(); String id=workspace.path("id").asText(), file=workspace.at("/files/0/id").asText(), hash=workspace.at("/files/0/originalHash").asText();
        String base="/api/editing-workspaces/"+id, path=base+"/files/"+file;
        mvc.perform(get(base).header("Authorization","Bearer "+other)).andExpect(status().isNotFound());
        mvc.perform(get(path).header("Authorization","Bearer "+other)).andExpect(status().isNotFound());
        var change=json.writeValueAsBytes(Map.of("revision",1,"originalHash",hash,"text","changed\n"));
        mvc.perform(put(path).header("Authorization","Bearer "+other).contentType(MediaType.APPLICATION_JSON).content(change)).andExpect(status().isNotFound());
        var next=json.readTree(mvc.perform(put(path).header("Authorization","Bearer "+owner).contentType(MediaType.APPLICATION_JSON).content(change)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        mvc.perform(put(path).header("Authorization","Bearer "+owner).contentType(MediaType.APPLICATION_JSON).content(change)).andExpect(status().isConflict());
        var approval=json.writeValueAsBytes(Map.of("revision",2,"changedFileIds",List.of(file),"approved",true));
        mvc.perform(post(base+"/export/zip").header("Authorization","Bearer "+other).contentType(MediaType.APPLICATION_JSON).content(approval)).andExpect(status().isNotFound());
        mvc.perform(post(base+"/export/zip").header("Authorization","Bearer "+owner).contentType(MediaType.APPLICATION_JSON).content(approval)).andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition","attachment; filename=\"securedeploy-edited-r2.zip\""));
        assertEquals(2,next.path("revision").asInt());
        assertArrayEquals(before,mvc.perform(get("/api/reviews/"+reviewId).header("Authorization","Bearer "+owner)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        mvc.perform(delete(base).header("Authorization","Bearer "+owner)).andExpect(status().isOk());
        mvc.perform(get(path).header("Authorization","Bearer "+owner)).andExpect(status().isNotFound());
    }
    @Test void hugeJsonAndUnauthenticatedRequestsRejected() throws Exception {
        mvc.perform(get("/api/editing-workspaces/unknown")).andExpect(status().isUnauthorized());
        mvc.perform(put("/api/editing-workspaces/a/files/b").header("Authorization","Bearer "+owner).contentType(MediaType.APPLICATION_JSON).content("x".repeat(1024*1024+1))).andExpect(status().isPayloadTooLarge());
    }
    @Test void githubMockAcquisitionUsesStoredRevisionAndRevokedAccessFails() throws Exception {
        var review=reviews.findById(reviewId).orElseThrow(); var project=review.getProject();
        var github = new ReviewEntity("github",ReviewSourceType.GITHUB,"https://github.com/fixture/editor",1,0,100,"READY"); github.assignProject(project);
        var metadata=new GitHubSourceSnapshot("fixture","editor","https://github.com/fixture/editor","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(3L,2L,true);
        github.attachSourceMetadata(metadata); reviews.saveAndFlush(github);
        when(sources.github(anyLong(),eq(metadata))).thenReturn(List.of(new SourceArchive.Entry("index.ts","original\n".getBytes(StandardCharsets.UTF_8),false,0100644)));
        var result=json.readTree(mvc.perform(post("/api/editing-workspaces/github/"+github.getId()).header("Authorization","Bearer "+owner)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertEquals("EXACT_GIT_COMMIT",result.path("identityStatus").asText()); assertEquals("a".repeat(40),result.path("sourceRevision").asText());
        mvc.perform(delete("/api/editing-workspaces/"+result.path("id").asText()).header("Authorization","Bearer "+owner)).andExpect(status().isOk());
        when(sources.github(anyLong(),eq(metadata))).thenThrow(com.securedeploy.github.app.GitHubAppException.denied());
        mvc.perform(post("/api/editing-workspaces/github/"+github.getId()).header("Authorization","Bearer "+owner)).andExpect(status().isForbidden());
    }
}
