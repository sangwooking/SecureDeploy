package com.securedeploy.upload.model;

import java.nio.file.Path;

public record ExtractedProject(
        String projectName,
        Path workspacePath,
        Path projectRoot,
        com.securedeploy.project.coverage.CoverageLedger sourceExclusions
) {
    public ExtractedProject(String projectName, Path workspacePath, Path projectRoot) {
        this(projectName, workspacePath, projectRoot, null);
    }
}
