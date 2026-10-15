package com.securedeploy.github.model;

import java.nio.file.Path;

public record ClonedRepository(
        String repositoryName,
        String repositoryUrl,
        Path workspacePath,
        Path repositoryRoot,
        GitHubSourceSnapshot sourceMetadata
) {
    public ClonedRepository(String name, String url, Path workspace, Path root) {
        this(name, url, workspace, root, null);
    }
}
