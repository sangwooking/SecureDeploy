package com.securedeploy.editing;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.auth.service.*;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.project.service.ProjectLifecycleGuard;
import com.securedeploy.review.model.ReviewSourceType;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockMultipartFile;

class WorkspaceVaultTest {
    JdbcTemplate jdbc;ObjectMapper mapper=new ObjectMapper().findAndRegisterModules();
    String key=Base64.getEncoder().encodeToString(new byte[32]);
    AtomicLong user=new AtomicLong(1);AtomicReference<Instant> now=new AtomicReference<>(Instant.parse("2026-10-31T00:00:00Z"));
    CurrentUserService users=mock(CurrentUserService.class);ReviewAccessService reviews=mock(ReviewAccessService.class);
    EditingSourceService sources=mock(EditingSourceService.class);List<EditingWorkspaceService> services=new ArrayList<>();
    @BeforeEach void setup()throws Exception {
        jdbc=new JdbcTemplate(new DriverManagerDataSource("jdbc:h2:mem:"+UUID.randomUUID()+";MODE=PostgreSQL;DB_CLOSE_DELAY=-1","sa",""));
        for(String table:List.of("users","projects","reviews")) {jdbc.execute("create table "+table+"(id bigint primary key)");jdbc.update("insert into "+table+" values(1)");}
        jdbc.execute(new String(getClass().getResourceAsStream("/db/epic01/V001__encrypted_workspaces.sql").readAllBytes(),StandardCharsets.UTF_8));
        when(users.currentUserId()).thenAnswer(i->user.get());
        var review=new ReviewEntity("fixture",ReviewSourceType.ZIP,null,1,0,100,"READY");
        var project=mock(ProjectEntity.class);when(project.getId()).thenReturn(1L);review.assignProject(project);
        when(reviews.findAccessibleReviewWithVulnerabilities(anyLong(),anyString())).thenReturn(review);
    }
    @AfterEach void cleanup(){services.forEach(EditingWorkspaceService::shutdown);}
    WorkspaceVault vault(){return new WorkspaceVault(jdbc,mapper,true,key,"test-key-v1",3600);}
    EditingWorkspaceService service(){var clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now.get();}};
        var s=new EditingWorkspaceService(reviews,users,sources,clock,new ProjectLifecycleGuard(),vault());services.add(s);return s;}
    EditingWorkspaceService.Workspace open(EditingWorkspaceService s)throws Exception {
        return s.create(1,new MockMultipartFile("file","source.zip","application/zip",SourceArchive.zip(List.of(new SourceArchive.Entry("src/a.ts","const original = 1;\n".getBytes(StandardCharsets.UTF_8),false,0100644)))));
    }
    @Test void restartPreservesRevisionOwnershipOriginalHashDraftAndExportApproval()throws Exception {
        var first=service();var w=open(first);var f=w.files().get(0);
        var saved=first.save(w.id(),f.id(),new EditingWorkspaceService.Change(1,f.originalHash(),"const changed = 2;\n"),false);
        byte[] before=first.download(w.id(),"zip",new EditingWorkspaceService.Approval(2,saved.changedFileIds(),true)).bytes();
        first.shutdown();var second=service();var resumed=second.discover(1).workspace();
        assertEquals(w.id(),resumed.id());assertEquals(2,resumed.revision());assertEquals("ENCRYPTED_PERSISTENT",resumed.storageMode());
        assertEquals(f.originalHash(),resumed.files().get(0).originalHash());assertEquals("MANUAL",resumed.files().get(0).provenance().get(0).generator());
        assertEquals(1,resumed.exports().size());assertEquals("const changed = 2;\n",second.content(w.id(),f.id()).text());
        assertTrue(second.diff(w.id(),f.id()).patch().contains("+const changed = 2;"));
        assertArrayEquals(before,second.download(w.id(),"zip",new EditingWorkspaceService.Approval(2,resumed.changedFileIds(),true)).bytes());
        assertEquals(3,second.save(w.id(),f.id(),new EditingWorkspaceService.Change(2,f.originalHash(),"const changed = 3;\n"),false).revision());
        user.set(2);assertThrows(RuntimeException.class,()->second.get(w.id()));
    }
    @Test void staleTabAndIndependentServiceCannotOverwriteSavedDraft()throws Exception {
        var a=service();var w=open(a);var f=w.files().get(0);var b=service();assertEquals(1,b.get(w.id()).revision());
        a.save(w.id(),f.id(),new EditingWorkspaceService.Change(1,f.originalHash(),"const a = 1;\n"),false);
        assertThrows(EditingConflictException.class,()->b.save(w.id(),f.id(),new EditingWorkspaceService.Change(1,f.originalHash(),"const b = 2;\n"),false));
        assertEquals("const a = 1;\n",b.content(w.id(),f.id()).text());
        var row=vault().owner(1,now.get()).orElseThrow();
        vault().put(row.snapshot(),row.version());
        assertThrows(EditingConflictException.class,()->vault().put(row.snapshot(),row.version()));
    }
    @Test void ciphertextTamperingMetadataTamperingAndWrongOrMissingKeyFailClosed()throws Exception {
        var s=service();var w=open(s);byte[] payload=jdbc.queryForObject("select payload from editing_workspace_v1",byte[].class);
        assertFalse(new String(payload,StandardCharsets.ISO_8859_1).contains("const original"));
        byte[] corrupt=payload.clone();corrupt[20]^=1;jdbc.update("update editing_workspace_v1 set payload=?",corrupt);
        assertThrows(RuntimeException.class,()->s.get(w.id()));
        jdbc.update("update editing_workspace_v1 set payload=?",payload);
        jdbc.update("update editing_workspace_v1 set store_version=store_version+1");assertThrows(RuntimeException.class,()->s.get(w.id()));
        jdbc.update("update editing_workspace_v1 set store_version=store_version-1");
        byte[] other=new byte[32];other[0]=1;
        var wrong=new WorkspaceVault(jdbc,mapper,true,Base64.getEncoder().encodeToString(other),"test-key-v1",3600);
        assertThrows(RuntimeException.class,()->wrong.owner(1,now.get()));
        assertThrows(IllegalStateException.class,()->new WorkspaceVault(jdbc,mapper,true,"","test-key-v1",3600));
        assertThrows(IllegalStateException.class,()->new WorkspaceVault(jdbc,mapper,true,key,"",3600));
        assertDoesNotThrow(()->new WorkspaceVault(jdbc,mapper,false,"","",3600));
    }
    @Test void expiryDeletionAndForeignKeyCascadeNeverTouchReviewOrProject()throws Exception {
        var s=service();var w=open(s);now.set(now.get().plusSeconds(3601));assertThrows(RuntimeException.class,()->s.get(w.id()));
        assertEquals(1,vault().cleanup(now.get()));assertEquals(1,jdbc.queryForObject("select count(*) from reviews",Integer.class));
        var next=open(s);s.delete(next.id());assertThrows(RuntimeException.class,()->s.get(next.id()));assertEquals(0,jdbc.queryForObject("select count(*) from editing_workspace_v1",Integer.class));
        open(s);jdbc.update("delete from projects where id=1");assertEquals(0,jdbc.queryForObject("select count(*) from editing_workspace_v1",Integer.class));
        assertEquals(1,jdbc.queryForObject("select count(*) from reviews",Integer.class));
    }
    @Test void invalidHashesAndOversizeEditsCannotBecomeStoredData()throws Exception {
        var s=service();var w=open(s);var f=w.files().get(0);
        assertThrows(RuntimeException.class,()->s.save(w.id(),f.id(),new EditingWorkspaceService.Change(1,"wrong","no"),false));
        assertThrows(RuntimeException.class,()->s.save(w.id(),f.id(),new EditingWorkspaceService.Change(1,f.originalHash(),"x".repeat(SourceArchive.EDIT_BYTES+1)),false));
        assertEquals(1,s.get(w.id()).revision());
    }
    @Test void protectedSeparateKeyFileRejectsPublicSymlinkAndConflictingSources()throws Exception {
        var dir=java.nio.file.Files.createTempDirectory("releasegate-key-");var file=dir.resolve("key");
        try {
            java.nio.file.Files.setPosixFilePermissions(dir,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            java.nio.file.Files.writeString(file,key);java.nio.file.Files.setPosixFilePermissions(file,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            assertDoesNotThrow(()->new WorkspaceVault(jdbc,mapper,true,"","test-key-v1",86400,file.toString()));
            assertThrows(IllegalStateException.class,()->new WorkspaceVault(jdbc,mapper,true,key,"test-key-v1",86400,file.toString()));
            java.nio.file.Files.setPosixFilePermissions(file,java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
            assertThrows(IllegalStateException.class,()->new WorkspaceVault(jdbc,mapper,true,"","test-key-v1",86400,file.toString()));
            java.nio.file.Files.delete(file);java.nio.file.Files.createSymbolicLink(file,dir.resolve("missing"));
            assertThrows(IllegalStateException.class,()->new WorkspaceVault(jdbc,mapper,true,"","test-key-v1",86400,file.toString()));
        }finally{java.nio.file.Files.deleteIfExists(file);java.nio.file.Files.deleteIfExists(dir);}
    }
}
