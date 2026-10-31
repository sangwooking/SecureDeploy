package com.securedeploy.github.service;

import com.securedeploy.github.model.*;
import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.global.util.FileUtils;
import java.nio.file.*;
import java.time.Instant;
import java.util.concurrent.Semaphore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class GitHubRepositoryService {
    private static final Logger LOG = LoggerFactory.getLogger(GitHubRepositoryService.class);
    private final FileStorageProperties storage;
    private final GitHubSourceProperties properties;
    private final GitHubSnapshotFetcher fetcher;
    private final GitTreeExporter exporter;
    private final Semaphore slots = new Semaphore(2);

    public GitHubRepositoryService(FileStorageProperties storage, GitHubSourceProperties properties,
            GitHubSnapshotFetcher fetcher, GitTreeExporter exporter) {
        this.storage = storage; this.properties = properties; this.fetcher = fetcher; this.exporter = exporter;
    }
    public String validateAndNormalizeUrl(String input) { return GitHubRepositoryUrl.parse(input).canonicalUrl(); }

    public ClonedRepository clonePublicRepository(String input) {
        return collect(input, null,null);
    }
    public ClonedRepository cloneAuthorizedRepository(String input, GitHubReadCredential credential) {
        java.util.Objects.requireNonNull(credential);
        return collect(input, credential,null);
    }
    public ClonedRepository clonePublicRepository(String input,String commitSha){if(commitSha==null||!commitSha.matches("[a-f0-9]{40}"))throw new SecureDeployException(HttpStatus.BAD_REQUEST,"정확한 Commit SHA가 필요합니다.");return collect(input,null,commitSha);}
    public ClonedRepository cloneAuthorizedRepository(String input,GitHubReadCredential credential,String commitSha){java.util.Objects.requireNonNull(credential);if(commitSha==null||!commitSha.matches("[a-f0-9]{40}"))throw new SecureDeployException(HttpStatus.BAD_REQUEST,"정확한 Commit SHA가 필요합니다.");return collect(input,credential,commitSha);}
    private ClonedRepository collect(String input, GitHubReadCredential credential,String commitSha) {
        GitHubRepositoryUrl url = GitHubRepositoryUrl.parse(input);
        if (!slots.tryAcquire()) throw new SecureDeployException(HttpStatus.TOO_MANY_REQUESTS, "GitHub 분석 요청이 많습니다. 잠시 후 다시 시도해 주세요.");
        Path workspace = null;
        boolean complete = false;
        try (var budget = new CloneBudget(properties)) {
            Instant started = Instant.now();
            Path base = Files.createDirectories(Path.of(storage.getTempDir()).toAbsolutePath().normalize());
            workspace = Files.createTempDirectory(base, "github-");
            Path gitDirectory = workspace.resolve("objects.git");
            Path root = Files.createDirectory(workspace.resolve("source")).toRealPath();
            GitHubSnapshotFetcher.Revision revision;
            try { revision = commitSha!=null?fetcher.fetchExact(url,gitDirectory,budget,credential,commitSha):credential == null ? fetcher.fetch(url, gitDirectory, budget)
                    : fetcher.fetchAuthenticated(url, gitDirectory, budget, credential); }
            catch (Exception failed) { budget.check(); throw failed; }
            if(commitSha!=null&&!commitSha.equals(revision.commitSha()))throw new SecureDeployException(HttpStatus.CONFLICT,"요청한 Commit과 확보한 원본이 다릅니다. HEAD로 대체하지 않았습니다.");
            var exported = exporter.export(gitDirectory, root, revision.commitSha(), budget);
            budget.check();
            var metadata = new GitHubSourceSnapshot(url.owner(), url.repository(), url.canonicalUrl(),
                    revision.branch(), revision.commitSha(), revision.commitSha().substring(0, 7), exported.commitTimestamp(),
                    started, Instant.now(), null, 1, exported.submodules(), exported.lfsPointers(), exported.symlinks(), exported.limitations());
            complete = true;
            return new ClonedRepository(url.repository(), url.canonicalUrl(), workspace, root, metadata, exported.sourceExclusions());
        } catch (SecureDeployException rejected) {
            LOG.info("GitHub source collection rejected");
            throw rejected;
        } catch (Exception failed) {
            // No remote message, URL, credentials, stack trace, or repository content in diagnostics.
            LOG.warn("GitHub source collection failed: {}", failed.getClass().getSimpleName());
            throw new SecureDeployException(HttpStatus.BAD_GATEWAY, "GitHub에서 프로젝트를 가져오지 못했습니다. 저장소 URL 또는 연결 권한을 확인하고 잠시 후 다시 시도해 주세요.");
        } finally {
            if (!complete) FileUtils.deleteRecursively(workspace);
            slots.release();
        }
    }
}
