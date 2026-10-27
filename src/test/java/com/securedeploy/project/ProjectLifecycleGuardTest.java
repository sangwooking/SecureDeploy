package com.securedeploy.project;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.entity.UserEntity;
import com.securedeploy.project.service.ProjectLifecycleGuard;
import com.securedeploy.review.model.ReviewSourceType;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class ProjectLifecycleGuardTest {
    private final ProjectLifecycleGuard guard = new ProjectLifecycleGuard();

    static ProjectEntity project(long id, long owner, ReviewSourceType type, String name, String url, Long repository) {
        var project = mock(ProjectEntity.class);
        var user = mock(UserEntity.class);
        when(user.getId()).thenReturn(owner);
        when(project.getId()).thenReturn(id);
        when(project.getUser()).thenReturn(user);
        when(project.getSourceType()).thenReturn(type);
        when(project.getName()).thenReturn(name);
        when(project.getRepositoryUrl()).thenReturn(url);
        when(project.getGithubRepositoryId()).thenReturn(repository);
        return project;
    }

    @Test void referenceCountsAndDeletionAreMutuallyExclusiveWithoutBlockingOtherProjects() {
        var project = project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        var first = guard.work(1L); var second = guard.work(1L);
        conflict(() -> guard.deletion(project));
        first.close(); first.close();
        conflict(() -> guard.deletion(project));
        second.close();
        try (var deletion = guard.deletion(project)) {
            conflict(() -> guard.work(1L));
            try (var unrelated = guard.work(2L)) { assertThat(unrelated).isNotNull(); }
        }
        try (var resumed = guard.work(1L)) { assertThat(resumed).isNotNull(); }
    }

    @Test void reuseIdentitiesCoverZipPublicAndConnectedGithubIncludingLegacyResolvers() {
        var zip = project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        var github = project(2, 10, ReviewSourceType.GITHUB, "repo", "https://github.com/owner/repo", 99L);
        try (var acquisition = guard.zipAcquisition(10L)) { conflict(() -> guard.deletion(zip)); }
        try (var scan = guard.zip(10L, "one")) { conflict(() -> guard.deletion(zip)); }
        try (var legacy = guard.zip(null, "one")) { conflict(() -> guard.deletion(zip)); }
        try (var scan = guard.github(10L, "https://github.com/OWNER/REPO.git")) { conflict(() -> guard.deletion(github)); }
        try (var legacy = guard.github(null, "https://github.com/owner/repo")) { conflict(() -> guard.deletion(github)); }
        try (var scan = guard.connected(10L, 99)) { conflict(() -> guard.deletion(github)); }
        try (var deletion = guard.deletion(github)) {
            conflict(() -> guard.connected(10L, 99));
            conflict(() -> guard.github(10L, "https://github.com/owner/repo"));
        }
    }

    @Test void allReadersRemainUntilRollbackCompletionAndReleaseExactlyOnce() {
        var project = project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.initSynchronization();
        List<TransactionSynchronization> callbacks;
        try {
            var first = guard.work(1L); var second = guard.work(1L); var alias = guard.zip(10L, "one");
            first.close(); first.close(); second.close(); alias.close();
            callbacks = TransactionSynchronizationManager.getSynchronizations();
            assertThat(callbacks).hasSize(3);
            conflict(() -> guard.deletion(project));
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
        callbacks.forEach(callback -> callback.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
        try (var deletion = guard.deletion(project)) { assertThat(deletion).isNotNull(); }
    }

    @Test void simultaneousAcquisitionAndDeletionHaveExactlyOneWinner() throws Exception {
        var project = project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        var executor = Executors.newFixedThreadPool(2);
        try {
            for (int iteration = 0; iteration < 50; iteration++) {
                var start = new CyclicBarrier(2);
                var attempted = new CountDownLatch(2);
                var release = new CountDownLatch(1);
                Future<Boolean> work = executor.submit(() -> race(start, attempted, release, () -> guard.work(1L)));
                Future<Boolean> delete = executor.submit(() -> race(start, attempted, release, () -> guard.deletion(project)));
                assertThat(attempted.await(5, TimeUnit.SECONDS)).isTrue();
                release.countDown();
                assertThat(work.get(5, TimeUnit.SECONDS) ^ delete.get(5, TimeUnit.SECONDS)).isTrue();
            }
        } finally { executor.shutdownNow(); }
    }

    @Test void reservationsAreBoundedAndNormalReleaseReclaimsCapacity() {
        var leases = new ArrayList<ProjectLifecycleGuard.Lease>();
        for (long id = 0; id < 4096; id++) leases.add(guard.work(id));
        assertThatThrownBy(() -> guard.work(4096L)).isInstanceOfSatisfying(SecureDeployException.class,
                error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS));
        leases.forEach(ProjectLifecycleGuard.Lease::close);
        try (var reclaimed = guard.work(4096L)) { assertThat(reclaimed).isNotNull(); }
    }

    @Test void knownCleanupFailureStaysBlockedAndDoesNotAffectUnrelatedProject(@TempDir Path root) throws Exception {
        var project = project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        Path source = Files.writeString(root.resolve("source.txt"), "synthetic");
        var lease = guard.work(1L);
        assertThatThrownBy(() -> lease.cleanup(root, () -> { })).isInstanceOfSatisfying(SecureDeployException.class,
                error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        lease.close();
        assertThat(Files.readString(source)).isEqualTo("synthetic");
        conflict(() -> guard.deletion(project));
        try (var unrelated = guard.deletion(project(2, 11, ReviewSourceType.ZIP, "other", null, null))) {
            assertThat(unrelated).isNotNull();
        }
    }

    @Test void bestEffortFileUtilsCanReturnWithSourceRemainingAndDeletionStaysBlocked(@TempDir Path root) throws Exception {
        var project = project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        Path source = Files.writeString(root.resolve("source.txt"), "synthetic");
        var lease = guard.work(1L);
        Files.setPosixFilePermissions(root, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"));
        try {
            assertThatThrownBy(() -> lease.cleanup(root,
                    () -> com.securedeploy.global.util.FileUtils.deleteRecursively(root)))
                    .isInstanceOfSatisfying(SecureDeployException.class,
                            error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
            lease.close();
            assertThat(Files.exists(source)).isTrue();
            conflict(() -> guard.deletion(project));
        } finally {
            Files.setPosixFilePermissions(root, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        }
    }

    private boolean race(CyclicBarrier start, CountDownLatch attempted, CountDownLatch release,
            Callable<ProjectLifecycleGuard.Lease> acquire) throws Exception {
        start.await(5, TimeUnit.SECONDS);
        ProjectLifecycleGuard.Lease lease = null;
        try {
            try { lease = acquire.call(); }
            catch (SecureDeployException conflict) { assertThat(conflict.getStatus()).isEqualTo(HttpStatus.CONFLICT); }
            attempted.countDown();
            if (!release.await(5, TimeUnit.SECONDS)) throw new AssertionError("release timeout");
            return lease != null;
        } finally { if (lease != null) lease.close(); }
    }

    static void conflict(org.assertj.core.api.ThrowableAssert.ThrowingCallable operation) {
        assertThatThrownBy(operation).isInstanceOfSatisfying(SecureDeployException.class,
                error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.CONFLICT));
    }
}
