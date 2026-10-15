package com.securedeploy.github.service;

import com.securedeploy.github.GitSourceFixture;
import com.securedeploy.github.model.GitHubRepositoryUrl;
import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.global.util.FileUtils;
import com.securedeploy.project.service.ProjectFileCollector;
import java.nio.file.*;
import java.time.Duration;
import java.util.List;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.dircache.*;
import org.eclipse.jgit.lib.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;
import org.springframework.util.unit.DataSize;
import static org.assertj.core.api.Assertions.*;

class GitHubSourceTest {
    @TempDir Path temp;
    @Test void canonicalUrlIsStrictAndNeverContainsCredentialsOrAlternateTransports() {
        for (String input : List.of("https://github.com/Owner/Repo", "https://github.com/OWNER/Repo.git/", "https://github.com:443/owner/repo"))
            assertThat(GitHubRepositoryUrl.parse(input).canonicalUrl()).isEqualTo("https://github.com/owner/repo");
        for (String input : List.of("", "file:///etc/passwd", "ftp://github.com/a/b", "ssh://github.com/a/b", "git://github.com/a/b",
                "http://github.com/a/b", "https://localhost/a/b", "https://127.0.0.1/a/b", "https://github.com.evil.invalid/a/b",
                "https://user:synthetic@github.com/a/b", "https://github.com:22/a/b", "https://github.com/a/b?q=x", "https://github.com/a/b#x",
                "https://github.com/a/%2e%2e", "https://github.com/a/..", "https://github.com/../b", "https://github.com/a/b/tree/main", "https://github.com/a/.git",
                "https://github.com/a\\b/c", "https://github.com/a%2fb/c", "https://github.com/-owner/b"))
            assertThatThrownBy(() -> GitHubRepositoryUrl.parse(input)).isInstanceOf(SecureDeployException.class).hasMessageNotContaining("synthetic");
    }
    @Test void transportRejectsRedirectTargetsAndMapsPrivateNotFoundWithoutGuessing() throws Exception {
        var settings = new GitHubSourceProperties();
        try (var budget = new CloneBudget(settings)) {
            var url = GitHubRepositoryUrl.parse("https://github.com/fixture/repo");
            for (String target : List.of("https://localhost/info/refs", "file:///etc/passwd", "https://github.com/other/repo.git/info/refs?service=git-upload-pack",
                    "https://github.com/fixture/repo.git/objects/../other", "https://github.com/fixture/repo.git/info/refs?service=git-receive-pack"))
                assertThatThrownBy(() -> new PublicGitHubConnection(new java.net.URL(target), url, budget)).isInstanceOf(java.io.IOException.class);
            new PublicGitHubConnection(new java.net.URL(url.cloneUrl() + "/info/refs?service=git-upload-pack"), url, budget);
        }
        for (int status : List.of(401, 403, 404, 301, 302, 307, 308, 500, 429)) try (var budget = new CloneBudget(settings)) {
            assertThatThrownBy(() -> PublicGitHubConnection.validateResponse(status, budget)).isInstanceOf(SecureDeployException.class);
            if (status == 404) assertThatThrownBy(budget::check).hasMessageContaining("공개 GitHub 저장소만");
        }
    }
    @Test void deadlineTransferAndRequestBudgetsAreBounded() throws Exception {
        var config = new GitHubSourceProperties(); config.setTimeoutSeconds(1); config.setMaxRequests(1); config.setMaxDownloadSize(DataSize.ofBytes(5));
        try (var budget = new CloneBudget(config)) {
            budget.downloaded(5);
            assertThatThrownBy(() -> budget.downloaded(1)).isInstanceOf(SecureDeployException.class);
        }
        try (var budget = new CloneBudget(config)) {
            budget.request(); assertThatThrownBy(budget::request).isInstanceOf(SecureDeployException.class);
        }
        try (var budget = new CloneBudget(config)) {
            Thread.sleep(1100);
            assertThatThrownBy(budget::check).isInstanceOf(SecureDeployException.class).hasMessageContaining("너무 오래");
        }
    }
    @Test void nonMainBranchExportOmitsLinksLfsSubmodulesAndNeverRunsScripts() throws Exception {
        Path remote = temp.resolve("remote"); GitSourceFixture.create(remote);
        Files.writeString(remote.resolve(".gitmodules"), "[submodule \"outside\"]\n path = outside\n url = file:///not-a-real-target\n");
        Files.writeString(remote.resolve("large.ts"), "version https://git-lfs.github.com/spec/v1\noid sha256:" + "1".repeat(64) + "\nsize 999999\n");
        Files.createSymbolicLink(remote.resolve("escape.java"), Path.of("/not-a-real-target"));
        String sha;
        try (Git git = Git.open(remote.toFile())) {
            GitSourceFixture.commit(git);
            var cache = git.getRepository().lockDirCache();
            try {
                var editor = cache.editor();
                editor.add(new DirCacheEditor.PathEdit("outside") { public void apply(DirCacheEntry entry) { entry.setFileMode(FileMode.GITLINK); entry.setObjectId(ObjectId.fromString("1".repeat(40))); } });
                editor.commit();
            } finally { cache.unlock(); }
            sha = git.commit().setMessage("Submodule fixture").setAuthor("Fixture", "fixture@example.invalid").setCommitter("Fixture", "fixture@example.invalid").call().name();
        }
        var service = service(remote, limits());
        var clone = service.clonePublicRepository("https://github.com/fixture/project");
        try {
            assertThat(clone.sourceMetadata().commitSha()).isEqualTo(sha);
            assertThat(clone.sourceMetadata().analyzedBranch()).isEqualTo("develop");
            assertThat(clone.sourceMetadata().submoduleCount()).isEqualTo(1);
            assertThat(clone.sourceMetadata().lfsPointerCount()).isEqualTo(1);
            assertThat(clone.sourceMetadata().symlinkCount()).isEqualTo(1);
            assertThat(clone.sourceMetadata().limitations()).hasSize(3);
            for (String path : List.of("outside", "large.ts", "escape.java", ".git", "build", "node_modules")) assertThat(clone.repositoryRoot().resolve(path)).doesNotExist();
            assertThat(clone.repositoryRoot().resolve("frontend/package.json")).exists();
        } finally { FileUtils.deleteRecursively(clone.workspacePath()); }
        assertNoWorkspace();
    }
    @Test void allResourceRejectionsAndFetchFailureCleanWorkspace() throws Exception {
        Path remote = temp.resolve("remote"); GitSourceFixture.create(remote);
        for (int type = 0; type < 4; type++) {
            var limits = limits();
            if (type == 0) limits.setMaxArchiveEntries(2);
            if (type == 1) limits.setMaxExpandedSize(DataSize.ofBytes(30));
            if (type == 2) limits.setMaxAnalysisFileSize(DataSize.ofBytes(10));
            if (type == 3) limits.setMaxAnalysisTotalSize(DataSize.ofBytes(50));
            assertThatThrownBy(() -> service(remote, limits).clonePublicRepository("https://github.com/fixture/project"))
                    .isInstanceOf(SecureDeployException.class).satisfies(e -> assertThat(((SecureDeployException)e).getStatus()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE));
            assertNoWorkspace();
        }
        var limits = limits();
        var failed = new GitHubRepositoryService(limits, new GitHubSourceProperties(), (url, dir, budget) -> { Files.createDirectories(dir); throw new java.io.IOException("untrusted remote text"); }, new GitTreeExporter(limits, new ProjectFileCollector()));
        assertThatThrownBy(() -> failed.clonePublicRepository("https://github.com/fixture/project")).hasMessageNotContaining("untrusted remote text");
        assertNoWorkspace();
        for (String path : List.of("../x", "/x", "C:/x", "a/../../b", "a\\b", "a//b")) assertThatThrownBy(() -> GitTreeExporter.safePath(path)).isInstanceOf(java.io.IOException.class);
    }
    private FileStorageProperties limits() { var p = new FileStorageProperties(); p.setTempDir(temp.resolve("workspaces").toString()); return p; }
    private GitHubRepositoryService service(Path remote, FileStorageProperties limits) {
        return new GitHubRepositoryService(limits, new GitHubSourceProperties(), GitSourceFixture.fetcher(remote), new GitTreeExporter(limits, new ProjectFileCollector()));
    }
    private void assertNoWorkspace() throws Exception { try (var paths = Files.list(temp.resolve("workspaces"))) { assertThat(paths.toList()).isEmpty(); } }
}
