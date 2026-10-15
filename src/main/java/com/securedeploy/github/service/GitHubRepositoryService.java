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
            try { revision = fetcher.fetch(url, gitDirectory, budget); }
            catch (Exception failed) { budget.check(); throw failed; }
            var exported = exporter.export(gitDirectory, root, revision.commitSha(), budget);
            budget.check();
            var metadata = new GitHubSourceSnapshot(url.owner(), url.repository(), url.canonicalUrl(),
                    revision.branch(), revision.commitSha(), revision.commitSha().substring(0, 7), exported.commitTimestamp(),
                    started, Instant.now(), null, 1, exported.submodules(), exported.lfsPointers(), exported.symlinks(), exported.limitations());
            complete = true;
            return new ClonedRepository(url.repository(), url.canonicalUrl(), workspace, root, metadata);
        } catch (SecureDeployException rejected) {
            LOG.info("GitHub source collection rejected");
            throw rejected;
        } catch (Exception failed) {
            // No remote message, URL, credentials, stack trace, or repository content in diagnostics.
            LOG.warn("GitHub source collection failed: {}", failed.getClass().getSimpleName());
            throw new SecureDeployException(HttpStatus.BAD_GATEWAY, "GitHub에서 프로젝트를 가져오지 못했습니다. 공개 저장소 URL을 확인하고 잠시 후 다시 시도해 주세요.");
        } finally {
            if (!complete) FileUtils.deleteRecursively(workspace);
            slots.release();
        }
    }
}
