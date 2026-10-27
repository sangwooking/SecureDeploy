package com.securedeploy.editing;

import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.auth.service.ReviewAccessService;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.review.service.SecurityReviewFacade;
import jakarta.annotation.PreDestroy;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class WorkspaceScanService {
    public record Request(long revision, List<String> changedFileIds, boolean approved, boolean externalLookupAcknowledged) { }
    public record View(String id, String state, String workspaceId, long revision, String inputHash,
                       Long reviewId, String message, Instant capturedAt) { }
    private static final class Job {
        final String id = UUID.randomUUID().toString();
        final long user;
        final WorkspaceScanSnapshot source;
        final Instant deadline;
        volatile String state = "RUNNING", message = "수정본 검사 준비 중입니다.";
        volatile Long review;
        volatile Thread runner;
        volatile boolean finalizing;
        final com.securedeploy.project.service.ProjectLifecycleGuard.Lease lease;
        Job(EditingWorkspaceService.ScanInput input, Instant deadline,
                com.securedeploy.project.service.ProjectLifecycleGuard.Lease lease) {
            this.lease = lease;
            user = input.userId();
            var p = input.provenance();
            // Polling retains only bounded identity facts; the complete file manifest belongs to the saved Review.
            source = new WorkspaceScanSnapshot(p.schemaVersion(), p.workspaceId(), p.userId(), p.originalReviewId(),
                    p.revision(), p.sourceRevision(), p.identityStatus(), p.inputHash(), p.capturedAt(), null, p.baselineVerified(), List.of(), "");
            this.deadline = deadline;
        }
        View view() { return new View(id, state, source.workspaceId(), source.revision(), source.inputHash(), review, message, source.capturedAt()); }
    }
    private final EditingWorkspaceService workspaces;
    private final CurrentUserService users;
    private final ReviewAccessService reviews;
    private final SecurityReviewFacade facade;
    private final WorkspaceScanPersistence persistence;
    private final Clock clock;
    private final Duration timeout;
    private final Path tempBase;
    private final Map<String, Job> jobs = new LinkedHashMap<>();
    private final Map<Long, List<Instant>> calls = new HashMap<>();
    private Job active;
    private volatile boolean closed;
    private final ExecutorService executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, new SynchronousQueue<>(), r -> {
        var t = new Thread(r, "workspace-standard-scan"); t.setDaemon(true); return t;
    });
    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
        var t = new Thread(r, "workspace-scan-deadline"); t.setDaemon(true); return t;
    });
    @org.springframework.beans.factory.annotation.Autowired
    public WorkspaceScanService(EditingWorkspaceService workspaces, CurrentUserService users, ReviewAccessService reviews,
            SecurityReviewFacade facade, WorkspaceScanPersistence persistence, com.securedeploy.global.config.FileStorageProperties storage) {
        this(workspaces, users, reviews, facade, persistence, Clock.systemUTC(), Duration.ofMinutes(2), Path.of(storage.getTempDir()).toAbsolutePath().normalize());
    }
    WorkspaceScanService(EditingWorkspaceService workspaces, CurrentUserService users, ReviewAccessService reviews,
            SecurityReviewFacade facade, WorkspaceScanPersistence persistence, Clock clock, Duration timeout) {
        this(workspaces, users, reviews, facade, persistence, clock, timeout,
                Path.of(System.getProperty("java.io.tmpdir"), "securedeploy-workspace-scans"));
    }
    private WorkspaceScanService(EditingWorkspaceService workspaces, CurrentUserService users, ReviewAccessService reviews,
            SecurityReviewFacade facade, WorkspaceScanPersistence persistence, Clock clock, Duration timeout, Path tempBase) {
        this.workspaces = workspaces; this.users = users; this.reviews = reviews;
        this.facade = facade; this.persistence = persistence; this.clock = clock; this.timeout = timeout; this.tempBase = tempBase;
        watchdog.scheduleWithFixedDelay(this::checkDeadline, 1, 1, TimeUnit.SECONDS);
    }
    @jakarta.annotation.PostConstruct public void cleanupInterruptedScans() throws java.io.IOException { EditingGitLease.cleanup(tempBase); }
    public synchronized View start(String id, Request request) {
        if (closed) throw fail(HttpStatus.SERVICE_UNAVAILABLE, "검사 실행기를 사용할 수 없습니다.");
        long user = users.currentUserId();
        var workspace = workspaces.get(id);
        if (request == null || !request.approved() || !request.externalLookupAcknowledged()
                || request.revision() != workspace.revision() || !workspace.changedFileIds().equals(request.changedFileIds()))
            throw fail(HttpStatus.CONFLICT, "검사할 revision·변경 목록과 외부 취약점 정보 조회 범위를 확인해 주세요.");
        var existing = jobs.values().stream().filter(j -> j.user == user && j.source.workspaceId().equals(id)
                && j.source.revision() == request.revision()).findFirst();
        if (existing.isPresent()) return existing.get().view();
        Instant now = clock.instant();
        jobs.values().removeIf(j -> j != active && j.source.capturedAt().plusSeconds(3600).isBefore(now));
        calls.values().forEach(list -> list.removeIf(at -> !at.plusSeconds(3600).isAfter(now)));
        calls.entrySet().removeIf(e -> e.getValue().isEmpty());
        if (active != null || jobs.size() >= 512 || calls.size() >= 1000 && !calls.containsKey(user)
                || calls.getOrDefault(user, List.of()).size() >= 4)
            throw fail(HttpStatus.TOO_MANY_REQUESTS, "수정본 검사 사용 한도 또는 동시 검사 한도에 도달했습니다. 잠시 후 확인해 주세요.");
        var input = workspaces.captureScan(id, request.revision());
        com.securedeploy.project.service.ProjectLifecycleGuard.Lease lease;
        try { lease = workspaces.retainScanLease(id); }
        catch (RuntimeException failure) { input.close(); throw failure; }
        var job = new Job(input, now.plus(timeout), lease);
        job.message = "저장된 수정본을 STANDARD로 검사하고 있습니다.";
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        active = job; jobs.put(job.id, job);
        calls.computeIfAbsent(user, ignored -> new ArrayList<>()).add(now);
        try {
            executor.execute(() -> {
                var context = SecurityContextHolder.createEmptyContext(); context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
                try { run(job, input); }
                finally { SecurityContextHolder.clearContext(); }
            });
        } catch (RejectedExecutionException stopped) {
            input.close(); job.lease.close(); active = null; jobs.remove(job.id); calls.get(user).remove(now);
            throw fail(HttpStatus.SERVICE_UNAVAILABLE, "검사 실행기를 사용할 수 없습니다.");
        }
        return job.view();
    }
    public synchronized View get(String id) {
        var job = jobs.get(id);
        if (job == null || job.user != users.currentUserId()) throw fail(HttpStatus.NOT_FOUND, "검사 작업을 찾을 수 없습니다.");
        reviews.findAccessibleReviewWithVulnerabilities(job.source.originalReviewId(), "분석 결과에 접근할 수 없습니다.");
        if (job.review != null) reviews.findAccessibleReviewWithVulnerabilities(job.review, "분석 결과에 접근할 수 없습니다.");
        return job.view();
    }
    private void run(Job job, EditingWorkspaceService.ScanInput input) {
        EditingGitLease lease = null; job.runner = Thread.currentThread();
        try (input) {
            guard(job);
            lease = EditingGitLease.open(tempBase);
            Path root = Files.createDirectory(lease.root().resolve("source"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            SourceArchive.validate(input.entries());
            for (var e : input.entries()) {
                timeGuard(job);
                Path target = root.resolve(SourceArchive.safePath(e.path(), e.directory())).normalize();
                if (!target.startsWith(root)) throw SourceArchive.invalid();
                if (e.directory()) Files.createDirectories(target);
                else {
                    Files.createDirectories(target.getParent());
                    Files.write(target, e.bytes(), StandardOpenOption.CREATE_NEW);
                    Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
                }
            }
            Path analysisRoot = input.provenance().baselineVerified() ? root
                    : com.securedeploy.upload.service.ZipExtractService.findProjectRoot(root);
            var scanInput = new EditingWorkspaceService.ScanInput(input.userId(), input.name(),
                    input.provenance().withAnalysisRoot(root.relativize(analysisRoot).toString().replace('\\', '/')), input.entries());
            var outcome = facade.analyzeWorkspace(input.name(), analysisRoot);
            guard(job);
            var saved = workspaces.whileScanLive(job.source.workspaceId(), () -> {
                job.finalizing = true;
                return persistence.save(scanInput, outcome, () -> guard(job));
            });
            job.review = saved.reviewId(); job.message = "고정된 revision의 검사 결과를 저장했습니다. 실제 운영 안전성이나 취약점 해결을 보증하지 않습니다.";
            job.state = "SUCCEEDED";
        } catch (Exception | LinkageError failure) {
            if (!clock.instant().isBefore(job.deadline)) {
                job.state = "TIMED_OUT";
                job.message = "검사 시간이 초과되었습니다. 결과를 저장하거나 해결로 처리하지 않았습니다.";
            }
            if (!"TIMED_OUT".equals(job.state)) {
                job.state = "FAILED";
                job.message = "수정본 검사를 완료하지 못했습니다. 만료·삭제·검사 범위·실행 제한을 확인해 주세요. 실패를 해결 또는 0건으로 처리하지 않았습니다.";
            }
        } finally {
            Thread.interrupted();
            if (lease != null) {
                try { lease.close(); } catch (java.io.IOException cleanupFailure) {
                    job.lease.retainAfterCleanupFailure();
                    job.message = "검사 임시 파일 정리를 완료하지 못했습니다. 관리자 확인이 필요합니다.";
                }
            }
            job.runner = null;
            synchronized (this) { if (active == job) active = null; }
            job.lease.close();
        }
    }
    private void guard(Job job) {
        timeGuard(job);
        workspaces.get(job.source.workspaceId());
    }
    private void timeGuard(Job job) {
        if (closed) throw fail(HttpStatus.SERVICE_UNAVAILABLE, "검사 실행기가 종료되었습니다.");
        if (!clock.instant().isBefore(job.deadline) || "TIMED_OUT".equals(job.state))
            throw fail(HttpStatus.REQUEST_TIMEOUT, "수정본 검사 시간이 초과되었습니다.");
    }
    private synchronized void checkDeadline() {
        if (active != null && !active.finalizing && !clock.instant().isBefore(active.deadline) && "RUNNING".equals(active.state)) {
            active.state = "TIMED_OUT"; active.message = "검사 시간이 초과되어 결과를 저장하지 않습니다. 실행 자원은 실제 작업 종료 후 반환합니다.";
            if (active.runner != null) active.runner.interrupt();
        }
    }
    @PreDestroy public void close() { closed = true; watchdog.shutdownNow(); executor.shutdownNow(); }
    private static SecureDeployException fail(HttpStatus status, String message) { return new SecureDeployException(status, message); }
}
