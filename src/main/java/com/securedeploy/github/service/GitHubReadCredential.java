package com.securedeploy.github.service;

import com.securedeploy.github.model.GitHubRepositoryUrl;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/** In-memory, single-repository credential; never serialize or put it in a Git URI/config. */
public final class GitHubReadCredential implements AutoCloseable {
    private final String cloneUrl;
    private final char[] token;
    private boolean closed;
    public GitHubReadCredential(GitHubRepositoryUrl repository, String token) {
        this.cloneUrl = repository.cloneUrl(); this.token = token.toCharArray();
    }
    synchronized String authorization(GitHubRepositoryUrl repository) {
        if (closed || !cloneUrl.equals(repository.cloneUrl())) throw new IllegalStateException("Credential scope mismatch");
        return "Basic " + Base64.getEncoder().encodeToString(("x-access-token:" + new String(token)).getBytes(StandardCharsets.UTF_8));
    }
    public synchronized void close() { Arrays.fill(token, '\0'); closed = true; }
    @Override public String toString() { return "GitHubReadCredential[redacted]"; }
}
