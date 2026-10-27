package com.securedeploy.editing;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.securedeploy.auth.service.*;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.project.service.ProjectLifecycleGuard;
import com.securedeploy.review.model.ReviewSourceType;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockMultipartFile;

class EditingWorkspaceLifecycleTest {
    final ProjectLifecycleGuard guard = new ProjectLifecycleGuard();
    final ReviewAccessService reviews = mock(ReviewAccessService.class);
    final CurrentUserService users = mock(CurrentUserService.class);
    final EditingSourceService sources = mock(EditingSourceService.class);
    final ProjectEntity project = mock(ProjectEntity.class);
    final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));
    EditingWorkspaceService workspaces;
    final ExecutorService executor = Executors.newSingleThreadExecutor();

    @BeforeEach void setup() {
        when(users.currentUserId()).thenReturn(1L);
        when(project.getId()).thenReturn(1L);
        when(project.getSourceType()).thenReturn(ReviewSourceType.ZIP);
        when(project.getName()).thenReturn("fixture");
        var user = mock(UserEntity.class); when(user.getId()).thenReturn(1L); when(project.getUser()).thenReturn(user);
        var review = new ReviewEntity("fixture", ReviewSourceType.ZIP, null, 1, 0, 100, "READY");
        review.assignProject(project);
        when(reviews.findAccessibleReviewWithVulnerabilities(anyLong(), anyString())).thenReturn(review);
        Clock clock = new Clock() {
            public ZoneId getZone() { return ZoneOffset.UTC; }
            public Clock withZone(ZoneId zone) { return this; }
            public Instant instant() { return now.get(); }
        };
        workspaces = new EditingWorkspaceService(reviews, users, sources, clock, guard);
    }
    @AfterEach void cleanup() { workspaces.shutdown(); executor.shutdownNow(); }

    @Test void openWorkspaceRefusesProjectDeletionWithoutClearingItAndCloseReleases() throws Exception {
        var workspace = workspaces.create(4, zip());
        conflict();
        assertThat(workspaces.get(workspace.id()).files()).hasSize(1);
        workspaces.delete(workspace.id());
        deletable();
    }

    @Test void expirationShutdownAndFailedAcquisitionReleaseTheirReferences() throws Exception {
        workspaces.create(4, zip());
        now.set(now.get().plusSeconds(1800));
        assertThatThrownBy(() -> workspaces.get("missing")).isInstanceOf(SecureDeployException.class);
        deletable();
        assertThatThrownBy(() -> workspaces.create(4, new MockMultipartFile("file", new byte[]{1}))).isInstanceOf(Exception.class);
        deletable();
        workspaces.create(4, zip());
        workspaces.shutdown();
        deletable();
    }

    @Test void sourceAcquisitionHoldsLeaseAndShutdownCannotPublishAnOrphanWorkspace() throws Exception {
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var zip = spy(zip());
        doAnswer(call -> {
            entered.countDown();
            if (!release.await(5, TimeUnit.SECONDS)) throw new AssertionError("release timeout");
            return call.callRealMethod();
        }).when(zip).getInputStream();
        var acquisition = executor.submit(() -> workspaces.create(4, zip));
        try {
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            conflict();
            workspaces.shutdown();
            conflict(); // Acquisition still owns the source buffers until it returns.
        } finally { release.countDown(); }
        assertThatThrownBy(() -> acquisition.get(5, TimeUnit.SECONDS)).isInstanceOf(ExecutionException.class);
        deletable();
    }

    @Test void deletionInProgressRejectsWorkspaceBeforeReadingSource() throws Exception {
        var zip = spy(zip());
        try (var deletion = guard.deletion(project)) {
            assertThatThrownBy(() -> workspaces.create(4, zip)).isInstanceOfSatisfying(SecureDeployException.class,
                    error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.CONFLICT));
            verify(zip, never()).getInputStream();
        }
        workspaces.create(4, zip);
    }

    private MockMultipartFile zip() throws Exception {
        return new MockMultipartFile("file", "fixture.zip", "application/zip", SourceArchive.zip(List.of(
                new SourceArchive.Entry("application.properties", "debug=true".getBytes(StandardCharsets.UTF_8), false, 0100644))));
    }
    private void conflict() {
        assertThatThrownBy(() -> guard.deletion(project)).isInstanceOfSatisfying(SecureDeployException.class,
                error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.CONFLICT));
    }
    private void deletable() { try (var deletion = guard.deletion(project)) { assertThat(deletion).isNotNull(); } }
}
