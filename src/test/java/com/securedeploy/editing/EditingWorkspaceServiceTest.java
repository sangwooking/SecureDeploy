package com.securedeploy.editing;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.securedeploy.auth.service.*;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.review.model.ReviewSourceType;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.MockMultipartFile;

class EditingWorkspaceServiceTest {
    final AtomicLong user = new AtomicLong(1);
    final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));
    final CurrentUserService users = mock(CurrentUserService.class);
    final ReviewAccessService reviews = mock(ReviewAccessService.class);
    final EditingSourceService sources = mock(EditingSourceService.class);
    EditingWorkspaceService service;
    @BeforeEach void setup() {
        when(users.currentUserId()).thenAnswer(i -> user.get());
        var review = new ReviewEntity("fixture", ReviewSourceType.ZIP, null, 1, 0, 100, "READY");
        var project = mock(com.securedeploy.persistence.entity.ProjectEntity.class);
        when(project.getId()).thenReturn(1L);
        review.assignProject(project);
        when(reviews.findAccessibleReviewWithVulnerabilities(anyLong(), anyString())).thenReturn(review);
        var clock = new Clock() { public ZoneId getZone() { return ZoneOffset.UTC; } public Clock withZone(ZoneId zone) { return this; } public Instant instant() { return now.get(); } };
        service = new EditingWorkspaceService(reviews, users, sources, clock);
    }
    @AfterEach void cleanup() { service.shutdown(); }
    EditingWorkspaceService.Workspace open(String value) throws Exception {
        var entries = List.of(new SourceArchive.Entry("src/app.ts", value.getBytes(StandardCharsets.UTF_8), false, 0100644),
                new SourceArchive.Entry("assets/image.bin", new byte[]{0, -1, 2}, false, 0100644));
        return service.create(4, new MockMultipartFile("file", "source.zip", "application/zip", SourceArchive.zip(entries)));
    }
    EditingWorkspaceService.FileInfo editable(EditingWorkspaceService.Workspace w) { return w.files().stream().filter(EditingWorkspaceService.FileInfo::editable).findFirst().orElseThrow(); }
    @Test void unverifiedZipIdentityAndOpaqueIdsNoSourceInTree() throws Exception {
        var w = open("const x='original';\n");
        assertEquals("UNVERIFIED_REUPLOAD", w.identityStatus()); assertEquals(64, w.sourceRevision().length());
        assertFalse(w.toString().contains("const x")); assertNotEquals("src/app.ts", editable(w).id());
        assertThrows(RuntimeException.class, () -> service.content(w.id(), "../src/app.ts"));
    }
    @Test void saveDiffApprovalAndZipPatchAgreeAndOriginalRemainsImmutable() throws Exception {
        var w = open("one\ntwo\n"); var f = editable(w);
        var next = service.save(w.id(), f.id(), new EditingWorkspaceService.Change(w.revision(), f.originalHash(), "one\nchanged\n"), false);
        assertEquals(2, next.revision()); assertEquals(f.originalHash(), editable(next).originalHash());
        var diff = service.diff(w.id(), f.id()).patch(); assertTrue(diff.contains("-two\n")); assertTrue(diff.contains("+changed\n"));
        var approval = new EditingWorkspaceService.Approval(next.revision(), next.changedFileIds(), true);
        byte[] zip = service.download(w.id(), "zip", approval).bytes();
        var restored = SourceArchive.read(new ByteArrayInputStream(zip));
        assertEquals("one\nchanged\n", new String(restored.stream().filter(e -> e.path().endsWith(".ts")).findFirst().orElseThrow().bytes(), StandardCharsets.UTF_8));
        assertArrayEquals(new byte[]{0, -1, 2}, restored.stream().filter(e -> e.path().endsWith(".bin")).findFirst().orElseThrow().bytes());
        assertEquals(diff, new String(service.download(w.id(), "patch", approval).bytes(), StandardCharsets.UTF_8));
        var reverted = service.save(w.id(), f.id(), new EditingWorkspaceService.Change(next.revision(), f.originalHash(), null), true);
        assertTrue(reverted.changedFileIds().isEmpty()); assertEquals("one\ntwo\n", service.content(w.id(), f.id()).text());
    }
    @Test void otherUserBlockedForEveryOperation() throws Exception {
        var w = open("a"); var f = editable(w); user.set(2);
        assertThrows(RuntimeException.class, () -> service.get(w.id()));
        assertThrows(RuntimeException.class, () -> service.content(w.id(), f.id()));
        assertThrows(RuntimeException.class, () -> service.diff(w.id(), f.id()));
        assertThrows(RuntimeException.class, () -> service.save(w.id(), f.id(), new EditingWorkspaceService.Change(1, f.originalHash(), "x"), false));
        assertThrows(RuntimeException.class, () -> service.download(w.id(), "zip", new EditingWorkspaceService.Approval(1, List.of(), true)));
        assertThrows(RuntimeException.class, () -> service.delete(w.id()));
    }
    @Test void staleHashRevisionAndApprovalFailClosed() throws Exception {
        var w = open("a"); var f = editable(w);
        assertThrows(RuntimeException.class, () -> service.save(w.id(), f.id(), new EditingWorkspaceService.Change(1, "wrong", "x"), false));
        var next = service.save(w.id(), f.id(), new EditingWorkspaceService.Change(1, f.originalHash(), "b"), false);
        assertThrows(RuntimeException.class, () -> service.save(w.id(), f.id(), new EditingWorkspaceService.Change(1, f.originalHash(), "stale"), false));
        for (var a : List.of(new EditingWorkspaceService.Approval(1, next.changedFileIds(), true), new EditingWorkspaceService.Approval(2, List.of(), true), new EditingWorkspaceService.Approval(2, next.changedFileIds(), false)))
            assertThrows(RuntimeException.class, () -> service.download(w.id(), "zip", a));
    }
    @Test void expiryDeletionAndRestartLoseSources() throws Exception {
        String expired = open("a").id(); now.set(now.get().plusSeconds(1800));
        assertThrows(RuntimeException.class, () -> service.get(expired));
        String id = open("b").id(); service.delete(id);
        assertThrows(RuntimeException.class, () -> service.get(id));
        String restart = open("c").id(); service.shutdown();
        assertThrows(RuntimeException.class, () -> service.get(restart));
    }
    @Test void onePerUserAndGlobalSlotsAndCreationFailuresReleaseSlots() throws Exception {
        assertThrows(RuntimeException.class, () -> service.create(4, new MockMultipartFile("file", new byte[]{1})));
        open("a"); assertThrows(RuntimeException.class, () -> open("b"));
        for (int n = 2; n <= 4; n++) { user.set(n); open("a"); }
        user.set(5); assertThrows(RuntimeException.class, () -> open("x"));
    }
    @Test void encodingBOMAndCrLfPreservedAndInvalidEditsRejected() throws Exception {
        var w = open("\ufeffone\r\ntwo\r\n"); var f = editable(w);
        assertTrue(service.content(w.id(), f.id()).bom());
        var next = service.save(w.id(), f.id(), new EditingWorkspaceService.Change(1, f.originalHash(), "one\nchanged\n"), false);
        assertEquals("one\r\nchanged\r\n", service.content(w.id(), f.id()).text());
        for (String invalid : List.of("bad\u0000", "\ud800", "a".repeat(SourceArchive.EDIT_BYTES + 1)))
            assertThrows(RuntimeException.class, () -> service.save(w.id(), f.id(), new EditingWorkspaceService.Change(next.revision(), f.originalHash(), invalid), false));
    }
    @Test void noChangesCannotExportAndBinaryCannotEdit() throws Exception {
        var w = open("a"); var binary = w.files().stream().filter(f -> !f.editable()).findFirst().orElseThrow();
        assertThrows(RuntimeException.class, () -> service.content(w.id(), binary.id()));
        assertThrows(RuntimeException.class, () -> service.download(w.id(), "zip", new EditingWorkspaceService.Approval(1, List.of(), true)));
    }
    @Test void revokedReviewClearsWorkspaceAndDeletionStillPossibleAfterReviewDeletion() throws Exception {
        var w = open("a");
        when(reviews.findAccessibleReviewWithVulnerabilities(anyLong(),anyString())).thenThrow(
                new com.securedeploy.global.error.SecureDeployException(org.springframework.http.HttpStatus.FORBIDDEN,"denied"));
        assertThrows(RuntimeException.class,()->service.get(w.id()));
        assertThrows(RuntimeException.class,()->service.get(w.id()));
        reset(reviews);
        var replacement = new ReviewEntity("fixture",ReviewSourceType.ZIP,null,1,0,100,"READY");
        var project = mock(com.securedeploy.persistence.entity.ProjectEntity.class);
        when(project.getId()).thenReturn(1L);
        replacement.assignProject(project);
        when(reviews.findAccessibleReviewWithVulnerabilities(anyLong(),anyString())).thenReturn(replacement);
        var other=open("b");
        when(reviews.findAccessibleReviewWithVulnerabilities(anyLong(),anyString())).thenThrow(new RuntimeException("review unavailable"));
        assertDoesNotThrow(()->service.delete(other.id()));
    }
}
