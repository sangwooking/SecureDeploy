package com.securedeploy.github.service;

import com.securedeploy.github.model.GitHubRepositoryUrl;
import java.nio.file.Path;

public interface GitHubSnapshotFetcher {
    record Revision(String branch, String commitSha) { }
    Revision fetch(GitHubRepositoryUrl url, Path gitDirectory, CloneBudget budget) throws Exception;
}
