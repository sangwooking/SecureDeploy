package com.securedeploy.github.service;

import com.securedeploy.github.model.GitHubRepositoryUrl;
import java.nio.file.Path;

public interface GitHubSnapshotFetcher {
    record Revision(String branch, String commitSha) { }
    Revision fetch(GitHubRepositoryUrl url, Path gitDirectory, CloneBudget budget) throws Exception;
    default Revision fetchExact(GitHubRepositoryUrl url, Path gitDirectory, CloneBudget budget,
            GitHubReadCredential credential, String commitSha) throws Exception {
        throw new UnsupportedOperationException("Exact revision collection unavailable");
    }
    default Revision fetchAuthenticated(GitHubRepositoryUrl url, Path gitDirectory, CloneBudget budget,
            GitHubReadCredential credential) throws Exception {
        throw new UnsupportedOperationException("Authenticated source collection unavailable");
    }
}
