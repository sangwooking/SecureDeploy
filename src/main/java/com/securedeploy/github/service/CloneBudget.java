package com.securedeploy.github.service;

import com.securedeploy.global.error.SecureDeployException;
import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import org.eclipse.jgit.lib.ProgressMonitor;
import org.springframework.http.HttpStatus;

/** One deadline and download allowance across advertisement, fetch, and materialization. */
public final class CloneBudget implements AutoCloseable, ProgressMonitor {
    private static final ScheduledExecutorService TIMER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "github-deadline"); t.setDaemon(true); return t;
    });
    private final long deadline;
    private final long maxBytes;
    private final int maxRequests;
    private final List<Closeable> streams = new ArrayList<>();
    private final ScheduledFuture<?> timeout;
    private long bytes;
    private int requests;
    private volatile SecureDeployException failure;
    private boolean closed;

    public CloneBudget(GitHubSourceProperties properties) {
        long seconds = Math.max(1, Math.min(300, properties.getTimeoutSeconds()));
        deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        maxBytes = Math.max(1, properties.getMaxDownloadSize().toBytes());
        maxRequests = Math.max(1, properties.getMaxRequests());
        timeout = TIMER.schedule(() -> { fail(HttpStatus.GATEWAY_TIMEOUT, "저장소를 가져오는 시간이 너무 오래 걸렸습니다."); closeStreams(); }, seconds, TimeUnit.SECONDS);
    }
    public void check() {
        if (System.nanoTime() >= deadline) fail(HttpStatus.GATEWAY_TIMEOUT, "저장소를 가져오는 시간이 너무 오래 걸렸습니다.");
        if (failure != null) throw failure;
        if (Thread.currentThread().isInterrupted()) throw new SecureDeployException(HttpStatus.SERVICE_UNAVAILABLE, "GitHub 수집이 중단되었습니다.");
    }
    public long remainingMillis() { check(); return Math.max(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())); }
    public synchronized void request() {
        check();
        if (++requests > maxRequests) throw fail(HttpStatus.PAYLOAD_TOO_LARGE, "GitHub 수집 요청 수가 허용 범위를 초과했습니다.");
    }
    public synchronized void downloaded(int count) {
        check(); bytes += Math.max(0, count);
        if (bytes > maxBytes) throw fail(HttpStatus.PAYLOAD_TOO_LARGE, "프로젝트가 분석 허용 크기를 초과했습니다.");
    }
    public synchronized void track(Closeable stream) throws java.io.IOException {
        if (closed || failure != null) { stream.close(); check(); throw new java.io.IOException("Closed collection"); }
        streams.add(stream);
    }
    public synchronized SecureDeployException fail(HttpStatus status, String message) {
        if (failure == null) failure = new SecureDeployException(status, message);
        return failure;
    }
    private synchronized void closeStreams() {
        closed = true;
        for (Closeable stream : streams) try { stream.close(); } catch (java.io.IOException ignored) { }
        streams.clear();
    }
    public void close() { timeout.cancel(false); closeStreams(); }
    public void start(int tasks) { check(); }
    public void beginTask(String title, int total) { check(); }
    public void update(int completed) { check(); }
    public void endTask() { check(); }
    public boolean isCancelled() { return failure != null || System.nanoTime() >= deadline || Thread.currentThread().isInterrupted(); }
    public void showDuration(boolean enabled) { }
}
