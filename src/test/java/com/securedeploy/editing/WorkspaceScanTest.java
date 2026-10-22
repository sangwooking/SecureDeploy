package com.securedeploy.editing;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.securedeploy.auth.service.*;
import com.securedeploy.github.model.GitHubSourceSnapshot;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.service.SecurityReviewFacade;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;

class WorkspaceScanTest {
    final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));
    final AtomicLong user = new AtomicLong(1);
    final CurrentUserService users = mock(CurrentUserService.class);
    final ReviewAccessService reviews = mock(ReviewAccessService.class);
    final EditingSourceService sources = mock(EditingSourceService.class);
    final SecurityReviewFacade facade = mock(SecurityReviewFacade.class);
    final WorkspaceScanPersistence persistence = mock(WorkspaceScanPersistence.class);
    final ReviewEntity review = mock(ReviewEntity.class);
    EditingWorkspaceService workspaces;
    WorkspaceScanService scans;
    EditingWorkspaceService.Workspace workspace;
    final Clock clock = new Clock() {
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId z) { return this; }
        public Instant instant() { return now.get(); }
    };
    @BeforeEach void setup() throws Exception {
        when(users.currentUserId()).thenAnswer(i -> user.get());
        when(reviews.findAccessibleReviewWithVulnerabilities(anyLong(), anyString())).thenReturn(review);
        when(review.getSourceType()).thenReturn(ReviewSourceType.GITHUB);
        when(review.getProjectName()).thenReturn("synthetic");
        when(review.getRepositoryUrl()).thenReturn("https://github.com/fixture/scan");
        when(review.getSourceMetadata()).thenReturn(new GitHubSourceSnapshot("fixture", "scan", "https://github.com/fixture/scan",
                "main", "a".repeat(40), "aaaaaaa", null, null, null, null, 1, 0, 0, 0, List.of()));
        when(sources.github(anyLong(), any())).thenAnswer(i -> List.of(
                new SourceArchive.Entry("application.properties", "debug=true\r\n".getBytes(StandardCharsets.UTF_8), false, 0100644),
                new SourceArchive.Entry("assets/data.bin", new byte[]{0, 1, 2}, false, 0100644)));
        workspaces = new EditingWorkspaceService(reviews, users, sources, clock);
        scans = new WorkspaceScanService(workspaces, users, reviews, facade, persistence, clock, Duration.ofSeconds(120));
        workspace = workspaces.create(4, null);
        when(persistence.save(any(), any(), any())).thenAnswer(i -> {
            ((Runnable)i.getArgument(2)).run();
            return new SecurityReviewResponse(99L, null, "synthetic", 1, 0, 100, "READY", List.of());
        });
    }
    @AfterEach void cleanup() { scans.close(); workspaces.shutdown(); }
    WorkspaceScanService.Request request() {
        return new WorkspaceScanService.Request(workspace.revision(), workspace.changedFileIds(), true, true);
    }
    WorkspaceScanService.View await(String id) throws Exception {
        for (int i=0; i<200; i++) {
            var view=scans.get(id); if (!view.state().equals("RUNNING")) return view; Thread.sleep(10);
        }
        throw new AssertionError("scan did not finish");
    }
    void save(String text) {
        var f=workspace.files().get(0);
        workspace=workspaces.save(workspace.id(), f.id(), new EditingWorkspaceService.Change(workspace.revision(), f.originalHash(), text), false);
    }
    @Test void capturedBytesAreIndependentAndEqualZipExportIncludingBinaryAndNewlines() throws Exception {
        save("debug=false\n");
        try (var input=workspaces.captureScan(workspace.id(),workspace.revision())) {
            var zip=workspaces.download(workspace.id(),"zip",new EditingWorkspaceService.Approval(workspace.revision(),workspace.changedFileIds(),true));
            var exported=SourceArchive.read(new ByteArrayInputStream(zip.bytes()));
            for(int i=0;i<exported.size();i++)assertArrayEquals(exported.get(i).bytes(),input.entries().get(i).bytes());
            assertEquals("a".repeat(40),input.provenance().sourceRevision());
            assertEquals("MANUAL",input.provenance().files().get(0).changeOrigin());
            save("debug=true\n# later\n");workspaces.delete(workspace.id());
            assertEquals("debug=false\r\n",new String(input.entries().get(0).bytes(),StandardCharsets.UTF_8));
        }
    }
    @Test void actualPinnedRevisionIsAnalyzedWhileEditingContinuesAndDuplicateRequestsReuseJob() throws Exception {
        var entered=new CountDownLatch(1); var release=new CountDownLatch(1);
        var observed=new AtomicReference<String>(); var temp=new AtomicReference<java.nio.file.Path>();
        when(facade.analyzeWorkspace(anyString(),any())).thenAnswer(i -> {
            java.nio.file.Path root=i.getArgument(1);temp.set(root);entered.countDown();release.await(2,TimeUnit.SECONDS);
            observed.set(Files.readString(root.resolve("application.properties")));return null;
        });
        var first=scans.start(workspace.id(),request());assertTrue(entered.await(2,TimeUnit.SECONDS));
        assertEquals(first.id(),scans.start(workspace.id(),request()).id());
        save("debug=false\n");release.countDown();assertEquals("SUCCEEDED",await(first.id()).state());
        assertEquals("debug=true\r\n",observed.get());
        for(int i=0;i<100&&Files.exists(temp.get());i++)Thread.sleep(10);
        assertFalse(Files.exists(temp.get()));verify(persistence,times(1)).save(any(),any(),any());
    }
    @Test void missingConsentStaleRevisionAndOtherUserAreRejected() {
        assertThrows(RuntimeException.class,()->scans.start(workspace.id(),new WorkspaceScanService.Request(1,List.of(),false,true)));
        assertThrows(RuntimeException.class,()->scans.start(workspace.id(),new WorkspaceScanService.Request(1,List.of(),true,false)));
        save("debug=false\n");
        assertThrows(RuntimeException.class,()->scans.start(workspace.id(),new WorkspaceScanService.Request(1,List.of(),true,true)));
        user.set(2);assertThrows(RuntimeException.class,()->scans.start(workspace.id(),request()));
        verifyNoInteractions(facade,persistence);
    }
    @Test void deletionDuringAnalysisPreventsResultSave() throws Exception {
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
        when(facade.analyzeWorkspace(anyString(),any())).thenAnswer(i->{entered.countDown();release.await(2,TimeUnit.SECONDS);return null;});
        var job=scans.start(workspace.id(),request());assertTrue(entered.await(2,TimeUnit.SECONDS));
        workspaces.delete(workspace.id());release.countDown();assertEquals("FAILED",await(job.id()).state());verifyNoInteractions(persistence);
    }
    @Test void expiryDuringAnalysisPreventsResultSave() throws Exception {
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
        when(facade.analyzeWorkspace(anyString(),any())).thenAnswer(i->{entered.countDown();release.await(2,TimeUnit.SECONDS);return null;});
        var job=scans.start(workspace.id(),request());assertTrue(entered.await(2,TimeUnit.SECONDS));
        now.set(now.get().plusSeconds(1801));release.countDown();assertNotEquals("SUCCEEDED",await(job.id()).state());verifyNoInteractions(persistence);
    }
    @Test void failedAnalysisIsNotZeroFindingsAndDoesNotCreateReview() throws Exception {
        when(facade.analyzeWorkspace(anyString(),any())).thenThrow(new IllegalStateException("synthetic internal detail must not leak"));
        var result=await(scans.start(workspace.id(),request()).id());assertEquals("FAILED",result.state());assertNull(result.reviewId());
        assertFalse(result.message().contains("internal detail"));verifyNoInteractions(persistence);
    }
    @Test void timeLimitKeepsSlotUntilWorkerActuallyReturnsAndNeverSaves() throws Exception {
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
        when(facade.analyzeWorkspace(anyString(),any())).thenAnswer(i->{
            entered.countDown();
            while(release.getCount()>0) { try { release.await(30,TimeUnit.MILLISECONDS); } catch(InterruptedException ignored) { } }
            return null;
        });
        var job=scans.start(workspace.id(),request());assertTrue(entered.await(2,TimeUnit.SECONDS));
        now.set(now.get().plusSeconds(121));
        for(int i=0;i<150&&scans.get(job.id()).state().equals("RUNNING");i++)Thread.sleep(10);
        assertEquals("TIMED_OUT",scans.get(job.id()).state());
        save("debug=false\n");assertThrows(RuntimeException.class,()->scans.start(workspace.id(),request()));
        release.countDown();Thread.sleep(50);verifyNoInteractions(persistence);
    }
    @Test void scanSnapshotBuffersAreWipedWhenClosedButOriginalSurvives() {
        var input=workspaces.captureScan(workspace.id(),workspace.revision());var bytes=input.entries().get(0).bytes();input.close();
        assertTrue(java.util.stream.IntStream.range(0,bytes.length).allMatch(i->bytes[i]==0));
        assertEquals("debug=true\r\n",workspaces.content(workspace.id(),workspace.files().get(0).id()).text());
    }
    @Test void sameRevisionFailureDoesNotAutomaticallyRetry() throws Exception {
        when(facade.analyzeWorkspace(anyString(),any())).thenThrow(new IllegalStateException());
        var first=await(scans.start(workspace.id(),request()).id());
        assertEquals(first.id(),scans.start(workspace.id(),request()).id());verify(facade,times(1)).analyzeWorkspace(anyString(),any());
    }
    @Test void quotaSurvivesWorkspaceRecreation() throws Exception {
        for(int i=0;i<4;i++) {
            if(i>0) { workspaces.delete(workspace.id()); workspace=workspaces.create(4,null); }
            await(scans.start(workspace.id(),request()).id());Thread.sleep(20);
        }
        workspaces.delete(workspace.id());workspace=workspaces.create(4,null);
        assertThrows(RuntimeException.class,()->scans.start(workspace.id(),request()));
    }
    @Test void savedJobRemainsReadableAfterWorkspaceDeletionButNotByOtherUser() throws Exception {
        var job=await(scans.start(workspace.id(),request()).id());workspaces.delete(workspace.id());
        assertEquals(99,scans.get(job.id()).reviewId());user.set(2);
        assertThrows(RuntimeException.class,()->scans.get(job.id()));
    }
    @Test void unverifiedZipHasNoAutomaticBaselineAndUsesCurrentManifest() throws Exception {
        workspaces.delete(workspace.id());when(review.getSourceType()).thenReturn(ReviewSourceType.ZIP);
        var bytes=SourceArchive.zip(List.of(new SourceArchive.Entry("application.properties","debug=true".getBytes(StandardCharsets.UTF_8),false,0100644)));
        workspace=workspaces.create(4,new org.springframework.mock.web.MockMultipartFile("file","synthetic.zip","application/zip",bytes));
        try(var input=workspaces.captureScan(workspace.id(),1)) {
            assertFalse(input.provenance().baselineVerified());assertEquals("UNVERIFIED_REUPLOAD",input.provenance().identityStatus());
            assertEquals(workspace.sourceRevision(),input.provenance().inputHash());
        }
    }
}
