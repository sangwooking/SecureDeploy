package com.securedeploy.github.model;

import java.time.Instant;
import java.util.List;

public record GitHubSourceSnapshot(String owner, String repository, String canonicalRepositoryUrl,
        String analyzedBranch, String commitSha, String shortCommitSha, Instant commitTimestamp,
        Instant cloneStartedAt, Instant clonedAt, Instant analyzedAt, int cloneDepth,
        int submoduleCount, int lfsPointerCount, int symlinkCount, List<String> limitations) {
    public GitHubSourceSnapshot analyzedNow() {
        return new GitHubSourceSnapshot(owner, repository, canonicalRepositoryUrl, analyzedBranch, commitSha,
                shortCommitSha, commitTimestamp, cloneStartedAt, clonedAt, Instant.now(), cloneDepth,
                submoduleCount, lfsPointerCount, symlinkCount, limitations);
    }
}
