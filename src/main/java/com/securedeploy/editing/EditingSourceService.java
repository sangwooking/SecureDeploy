package com.securedeploy.editing;

import com.securedeploy.github.app.*;
import com.securedeploy.github.model.*;
import com.securedeploy.github.service.*;
import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class EditingSourceService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(EditingSourceService.class);
    private final GitHubConnectionService connections;
    private final GitHubAppClient client;
    private final GitHubSnapshotFetcher fetcher;
    private final GitHubSourceProperties properties;
    private final FileStorageProperties storage;
    public EditingSourceService(GitHubConnectionService connections, GitHubAppClient client,
            GitHubSnapshotFetcher fetcher, GitHubSourceProperties properties, FileStorageProperties storage) {
        this.connections = connections; this.client = client; this.fetcher = fetcher; this.properties = properties; this.storage = storage;
    }
    @jakarta.annotation.PostConstruct
    public void cleanupInterruptedAcquisitions() throws IOException {
        EditingGitLease.cleanup(Path.of(storage.getTempDir()).toAbsolutePath().normalize());
    }
    List<SourceArchive.Entry> github(long user, GitHubSourceSnapshot source) {
        if (source == null || source.commitSha() == null || !source.commitSha().matches("[0-9a-f]{40}"))
            throw new SecureDeployException(HttpStatus.CONFLICT, "정확한 원본 commit이 기록되지 않았습니다. 새 기준으로 분석한 뒤 작업 공간을 열어 주세요.");
        var url = GitHubRepositoryUrl.parse(source.canonicalRepositoryUrl());
        boolean app = "GITHUB_APP".equals(source.accessMethod());
        if (Boolean.TRUE.equals(source.privateRepository()) && !app) throw denied();
        String token = null;
        try {
            if (app) {
                authorize(user, source, url);
                token = client.installationToken(source.installationId(), source.repositoryId());
            }
            try (var credential = token == null ? null : new GitHubReadCredential(url, token)) {
                var entries = collect(url, source.commitSha(), credential);
                if (app) authorize(user, source, url);
                return entries;
            }
        } finally { if (token != null) client.revokeInstallation(token); }
    }
    private void authorize(long user, GitHubSourceSnapshot source, GitHubRepositoryUrl url) {
        if (source.installationId() == null || source.repositoryId() == null) throw denied();
        var allowed = connections.authorize(user, source.installationId(), source.repositoryId());
        if (!url.canonicalUrl().equals(allowed.repositoryUrl())) throw denied();
    }
    private List<SourceArchive.Entry> collect(GitHubRepositoryUrl url, String sha, GitHubReadCredential credential) {
        String stage = "TEMP_LEASE";
        try (var budget = new CloneBudget(properties);
             var lease = EditingGitLease.open(Path.of(storage.getTempDir()).toAbsolutePath().normalize())) {
            Path git = lease.root().resolve("objects.git");
            stage = "FETCH_EXACT_COMMIT";
            var revision = fetcher.fetchExact(url, git, budget, credential, sha);
            if (!sha.equals(revision.commitSha())) throw denied();
            stage = "READ_COMMIT_TREE";
            var entries = readTree(git, sha, budget);
            stage = "TEMP_CLEANUP";
            return entries;
        } catch (SecureDeployException rejected) { throw rejected; }
        catch (Exception failed) {
            // Whitelisted stage and Java type only: no URL, SHA, remote message, source, or credentials.
            LOG.warn("Editing source acquisition stage={} errorType={}", stage, failed.getClass().getSimpleName());
            throw new SecureDeployException(HttpStatus.BAD_GATEWAY, "기록된 commit의 전체 원본을 확보하지 못했습니다. 권한과 원본 commit 보존 여부를 확인해 주세요. 최신 commit으로 대체하지 않았습니다.");
        }
    }
    private List<SourceArchive.Entry> readTree(Path git, String sha, CloneBudget budget) throws IOException {
        var entries = new ArrayList<SourceArchive.Entry>();
        long total = 0;
        try (var repository = new FileRepositoryBuilder().setGitDir(git.toFile()).setBare().build();
             var rev = new RevWalk(repository); var tree = new TreeWalk(repository)) {
            tree.addTree(rev.parseCommit(ObjectId.fromString(sha)).getTree());
            tree.setRecursive(true);
            while (tree.next()) {
                budget.check();
                if (entries.size() >= SourceArchive.MAX_FILES) throw SourceArchive.limit();
                var mode = tree.getFileMode(0);
                if (!mode.equals(FileMode.REGULAR_FILE) && !mode.equals(FileMode.EXECUTABLE_FILE))
                    throw new SecureDeployException(HttpStatus.UNPROCESSABLE_ENTITY, "링크 또는 submodule이 있어 전체 원본을 안전하게 편집할 수 없습니다. 제외한 원본으로 ZIP을 만들지 않았습니다.");
                String path = SourceArchive.safePath(java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(tree.getRawPath())).toString(), false);
                var blob = repository.open(tree.getObjectId(0), Constants.OBJ_BLOB);
                if (blob.getSize() > SourceArchive.MAX_BYTES - total) throw SourceArchive.limit();
                byte[] bytes;
                try (var input = blob.openStream()) { bytes = SourceArchive.bounded(input, (int) (SourceArchive.MAX_BYTES - total)); }
                total += bytes.length;
                if (bytes.length <= 1024 && new String(bytes, java.nio.charset.StandardCharsets.US_ASCII).startsWith("version https://git-lfs.github.com/spec/v1"))
                    throw new SecureDeployException(HttpStatus.UNPROCESSABLE_ENTITY, "LFS 원본을 확보하지 못해 전체 원본 편집을 중단했습니다.");
                entries.add(new SourceArchive.Entry(path, bytes, false, mode.getBits()));
            }
        }
        SourceArchive.validate(entries);
        return List.copyOf(entries);
    }
    private SecureDeployException denied() { return new SecureDeployException(HttpStatus.FORBIDDEN, "이 원본에 접근할 수 없습니다."); }
}
