package com.securedeploy.github.model;

import java.nio.file.Path;

public record ClonedRepository(
        String repositoryName,
        String repositoryUrl,
        Path workspacePath,
        Path repositoryRoot
) {
}
