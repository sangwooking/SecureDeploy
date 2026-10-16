package com.securedeploy.github.model;

import java.time.Instant;
import java.util.List;

public record GitHubSourceSnapshot(String owner, String repository, String canonicalRepositoryUrl,
        String analyzedBranch, String commitSha, String shortCommitSha, Instant commitTimestamp,
        Instant cloneStartedAt, Instant clonedAt, Instant analyzedAt, int cloneDepth,
        int submoduleCount, int lfsPointerCount, int symlinkCount, List<String> limitations,
        Long repositoryId, Long installationId, Boolean privateRepository, String accessMethod) {
    public GitHubSourceSnapshot(String owner, String repository, String canonicalRepositoryUrl,
            String analyzedBranch, String commitSha, String shortCommitSha, Instant commitTimestamp,
            Instant cloneStartedAt, Instant clonedAt, Instant analyzedAt, int cloneDepth,
            int submoduleCount, int lfsPointerCount, int symlinkCount, List<String> limitations) {
        this(owner, repository, canonicalRepositoryUrl, analyzedBranch, commitSha, shortCommitSha, commitTimestamp,
                cloneStartedAt, clonedAt, analyzedAt, cloneDepth, submoduleCount, lfsPointerCount, symlinkCount,
                limitations, null, null, null, "PUBLIC_ANONYMOUS");
    }
    public GitHubSourceSnapshot withAccess(Long repositoryId, Long installationId, boolean privateRepository) {
        return new GitHubSourceSnapshot(owner, repository, canonicalRepositoryUrl, analyzedBranch, commitSha,
                shortCommitSha, commitTimestamp, cloneStartedAt, clonedAt, analyzedAt, cloneDepth,
                submoduleCount, lfsPointerCount, symlinkCount, limitations, repositoryId, installationId, privateRepository, "GITHUB_APP");
    }
    public GitHubSourceSnapshot analyzedNow() {
        return new GitHubSourceSnapshot(owner, repository, canonicalRepositoryUrl, analyzedBranch, commitSha,
                shortCommitSha, commitTimestamp, cloneStartedAt, clonedAt, Instant.now(), cloneDepth,
                submoduleCount, lfsPointerCount, symlinkCount, limitations, repositoryId, installationId, privateRepository, accessMethod);
    }
}
