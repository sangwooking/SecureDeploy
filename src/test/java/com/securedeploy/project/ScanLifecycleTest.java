package com.securedeploy.project;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.github.app.PrivateGitHubSourceService;
import com.securedeploy.github.service.GitHubRepositoryService;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.project.service.*;
import com.securedeploy.review.model.*;
import com.securedeploy.review.service.SecurityReviewFacade;
import com.securedeploy.upload.model.*;
import com.securedeploy.upload.service.*;
import java.nio.file.Path;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockMultipartFile;

class ScanLifecycleTest {
    final ProjectLifecycleGuard guard = new ProjectLifecycleGuard();
    final ProjectService projects = mock(ProjectService.class);
    final CurrentUserService users = mock(CurrentUserService.class);
    final UploadService uploads = mock(UploadService.class);
    final ZipExtractService extracts = mock(ZipExtractService.class);
    final GitHubRepositoryService github = mock(GitHubRepositoryService.class);
    final PrivateGitHubSourceService connected = mock(PrivateGitHubSourceService.class);
    final ProjectScanner scanner = mock(ProjectScanner.class);
    final ExecutorService executor = Executors.newSingleThreadExecutor();
    SecurityReviewFacade facade;
    final CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
    static final String URL = "https://github.com/owner/repo";
    final RuntimeException stop = new IllegalStateException("synthetic acquisition stop");

    @BeforeEach void setup() {
        when(users.currentUserId()).thenReturn(10L);
        when(github.validateAndNormalizeUrl(anyString())).thenAnswer(call -> call.getArgument(0));
        facade = new SecurityReviewFacade(uploads, extracts, github, scanner, null, null, null, null,
                null, projects, users, null, null, null, null, null, null, null, connected, null, null, null, guard);
    }
    @AfterEach void cleanup() { release.countDown(); executor.shutdownNow(); }

    @Test void publicGithubRescanHoldsLeaseThroughoutCloneAndReleasesOnFailure() throws Exception {
        var project = ProjectLifecycleGuardTest.project(1, 10, ReviewSourceType.GITHUB, "repo", URL, null);
        when(projects.findOwnedProjectForRescan(1L, 10L, ReviewSourceType.GITHUB)).thenReturn(project);
        when(github.clonePublicRepository(URL)).thenAnswer(call -> pause());
        assertBlockedDuring(() -> facade.reviewGitHubRepository(1L, URL, ScanMode.STANDARD), project);
        verify(projects, times(2)).findOwnedProjectForRescan(1L, 10L, ReviewSourceType.GITHUB);
    }

    @Test void noIdPublicGithubAcquisitionBlocksDeletionOfReusedProject() throws Exception {
        var project = ProjectLifecycleGuardTest.project(1, 10, ReviewSourceType.GITHUB, "repo", URL, null);
        when(github.clonePublicRepository(URL)).thenAnswer(call -> pause());
        assertBlockedDuring(() -> facade.reviewGitHubRepository(URL, ScanMode.STANDARD), project);
    }

    @Test void noIdConnectedAcquisitionBlocksDeletionOfReusedProject() throws Exception {
        var project = ProjectLifecycleGuardTest.project(1, 10, ReviewSourceType.GITHUB, "repo", URL, 99L);
        when(connected.collect(10L, 20L, 99L)).thenAnswer(call -> pause());
        assertBlockedDuring(() -> facade.reviewConnectedGitHub(null, 20, 99, ScanMode.STANDARD), project);
    }

    @Test void zipRescanHoldsLeaseBeforeSourceUpload() throws Exception {
        var project = ProjectLifecycleGuardTest.project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        when(projects.findOwnedProjectForRescan(1L, 10L, ReviewSourceType.ZIP)).thenReturn(project);
        when(uploads.saveZip(any())).thenAnswer(call -> pause());
        assertBlockedDuring(() -> facade.reviewUploadedZip(1L, new MockMultipartFile("file", new byte[]{1})), project);
    }

    @Test void unresolvedZipAcquisitionBlocksDeletionBeforeNameIsKnown() throws Exception {
        var project = ProjectLifecycleGuardTest.project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        when(uploads.saveZip(any())).thenAnswer(call -> pause());
        assertBlockedDuring(() -> facade.reviewUploadedZip(new MockMultipartFile("file", new byte[]{1})), project);
    }

    @Test void resolvedZipScanTransfersToNameLeaseAndDoesNotBlockOtherNames(@TempDir Path temp) throws Exception {
        var project = ProjectLifecycleGuardTest.project(1, 10, ReviewSourceType.ZIP, "one", null, null);
        var other = ProjectLifecycleGuardTest.project(2, 10, ReviewSourceType.ZIP, "other", null, null);
        when(uploads.saveZip(any())).thenReturn(new UploadedArchive("one.zip", temp, temp.resolve("one.zip")));
        when(extracts.extract(any())).thenReturn(new ExtractedProject("one", temp, temp, null));
        when(scanner.scan(temp)).thenAnswer(call -> pause());
        var scan = executor.submit(() -> facade.reviewUploadedZip(new MockMultipartFile("file", new byte[]{1})));
        try {
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            ProjectLifecycleGuardTest.conflict(() -> guard.deletion(project));
            try (var unrelated = guard.deletion(other)) { assertThat(unrelated).isNotNull(); }
        } finally { release.countDown(); }
        assertThatThrownBy(() -> scan.get(5, TimeUnit.SECONDS)).isInstanceOf(ExecutionException.class).hasCause(stop);
        try (var deletion = guard.deletion(project)) { assertThat(deletion).isNotNull(); }
    }

    @Test void deletionRejectsNewWorkBeforeExternalAcquisitionAndPermissionCheckStillRunsFirst() {
        var project = ProjectLifecycleGuardTest.project(1, 10, ReviewSourceType.GITHUB, "repo", URL, null);
        when(projects.findOwnedProjectForRescan(1L, 10L, ReviewSourceType.GITHUB)).thenReturn(project);
        try (var deletion = guard.deletion(project)) {
            ProjectLifecycleGuardTest.conflict(() -> facade.reviewGitHubRepository(1L, URL));
            verify(github, never()).clonePublicRepository(anyString());
            when(projects.findOwnedProjectForRescan(1L, 10L, ReviewSourceType.GITHUB))
                    .thenThrow(new SecureDeployException(HttpStatus.FORBIDDEN, "denied"));
            assertThatThrownBy(() -> facade.reviewGitHubRepository(1L, URL)).isInstanceOfSatisfying(SecureDeployException.class,
                    error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.FORBIDDEN));
        }
    }

    private Object pause() throws Exception {
        entered.countDown();
        if (!release.await(5, TimeUnit.SECONDS)) throw new AssertionError("release timeout");
        throw stop;
    }
    private void assertBlockedDuring(Callable<?> operation, ProjectEntity project) throws Exception {
        var scan = executor.submit(operation);
        try {
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            ProjectLifecycleGuardTest.conflict(() -> guard.deletion(project));
        } finally { release.countDown(); }
        assertThatThrownBy(() -> scan.get(5, TimeUnit.SECONDS)).isInstanceOf(ExecutionException.class).hasCause(stop);
        try (var deletion = guard.deletion(project)) { assertThat(deletion).isNotNull(); }
    }
}
