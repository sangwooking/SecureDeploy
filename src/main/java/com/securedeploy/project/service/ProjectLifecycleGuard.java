package com.securedeploy.project.service;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.review.model.ReviewSourceType;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Process-local reservations; database row locks remain necessary for persistence. */
@Component
public class ProjectLifecycleGuard {
    private record Key(String kind, Long owner, String identity) { }
    private static final class Entry { int readers; boolean deleting; }
    private static final int MAX_KEYS = 4096, MAX_LEASES = 8192;
    private final Map<Key, Entry> entries = new HashMap<>();
    private int leases;

    public final class Lease implements AutoCloseable {
        private final List<Key> keys;
        private final boolean deleting;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicBoolean cleanupFailed = new AtomicBoolean();
        private Lease(List<Key> keys, boolean deleting) { this.keys = keys; this.deleting = deleting; }
        public void retainAfterCleanupFailure() { cleanupFailed.set(true); }
        public void cleanup(Path root, Runnable cleanup) {
            try {
                cleanup.run();
                if (root != null && !Files.notExists(root, LinkOption.NOFOLLOW_LINKS))
                    throw new IllegalStateException("Temporary source removal could not be verified");
            } catch (RuntimeException failure) {
                retainAfterCleanupFailure();
                throw new SecureDeployException(HttpStatus.SERVICE_UNAVAILABLE,
                        "임시 소스 정리를 확인하지 못했습니다. 프로젝트 삭제를 차단했습니다. 관리자 확인이 필요합니다.");
            }
        }
        @Override public void close() {
            if (!closed.compareAndSet(false, true)) return;
            // A known source remnant must not silently make the project deletable again.
            if (cleanupFailed.get()) return;
            if (TransactionSynchronizationManager.isActualTransactionActive()
                    && TransactionSynchronizationManager.isSynchronizationActive()) {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override public void afterCompletion(int status) { release(Lease.this); }
                });
            } else release(this);
        }
    }

    public Lease work(Long projectId) {
        return reserve(List.of(projectKey(Objects.requireNonNull(projectId))), false);
    }
    public Lease zipAcquisition(Long owner) { return reserve(List.of(zipOwner(owner)), false); }
    public Lease zip(Long owner, String name) { return reserve(List.of(zipKey(owner, name)), false); }
    public Lease github(Long owner, String url) { return reserve(List.of(githubKey(owner, url)), false); }
    public Lease connected(Long owner, long repositoryId) { return reserve(List.of(connectedKey(owner, repositoryId)), false); }

    public Lease deletion(ProjectEntity project) {
        var keys = new LinkedHashSet<Key>();
        keys.add(projectKey(Objects.requireNonNull(project.getId())));
        Long owner = project.getUser() == null ? null : project.getUser().getId();
        if (project.getSourceType() == ReviewSourceType.ZIP) {
            keys.add(zipOwner(owner));
            keys.add(zipKey(owner, project.getName()));
            keys.add(zipKey(null, project.getName())); // Legacy ownerless resolver may reuse owned rows.
        }
        if (project.getSourceType() == ReviewSourceType.GITHUB) {
            try {
                keys.add(githubKey(owner, project.getRepositoryUrl()));
                keys.add(githubKey(null, project.getRepositoryUrl()));
            } catch (SecureDeployException invalidLegacyUrl) {
                // Malformed legacy URLs cannot enter the public acquisition path.
            }
            if (project.getGithubRepositoryId() != null) keys.add(connectedKey(owner, project.getGithubRepositoryId()));
        }
        return reserve(List.copyOf(keys), true);
    }

    private synchronized Lease reserve(List<Key> keys, boolean deleting) {
        for (Key key : keys) {
            var entry = entries.get(key);
            if (entry != null && (entry.deleting || deleting && entry.readers != 0))
                throw new SecureDeployException(HttpStatus.CONFLICT, "프로젝트에서 다른 작업이 진행 중입니다. 작업이 끝난 후 다시 시도해 주세요.");
        }
        long added = keys.stream().filter(key -> !entries.containsKey(key)).count();
        if (leases >= MAX_LEASES || entries.size() + added > MAX_KEYS)
            throw new SecureDeployException(HttpStatus.TOO_MANY_REQUESTS, "프로젝트 작업 한도에 도달했습니다. 잠시 후 다시 시도해 주세요.");
        for (Key key : keys) {
            var entry = entries.computeIfAbsent(key, ignored -> new Entry());
            if (deleting) entry.deleting = true;
            else entry.readers++;
        }
        leases++;
        return new Lease(keys, deleting);
    }

    private synchronized void release(Lease lease) {
        for (Key key : lease.keys) {
            var entry = entries.get(key);
            if (lease.deleting) entry.deleting = false;
            else entry.readers--;
            if (!entry.deleting && entry.readers == 0) entries.remove(key);
        }
        leases--;
    }

    private static Key projectKey(Long id) { return new Key("PROJECT", null, id.toString()); }
    private static Key zipOwner(Long owner) { return new Key("ZIP_ACQUISITION", owner, ""); }
    private static Key zipKey(Long owner, String name) { return new Key("ZIP", owner, Objects.requireNonNull(name)); }
    private static Key connectedKey(Long owner, long id) { return new Key("CONNECTED", owner, Long.toString(id)); }
    private static Key githubKey(Long owner, String url) {
        return new Key("GITHUB", owner, com.securedeploy.github.model.GitHubRepositoryUrl.parse(url).canonicalUrl().toLowerCase(Locale.ROOT));
    }
}
