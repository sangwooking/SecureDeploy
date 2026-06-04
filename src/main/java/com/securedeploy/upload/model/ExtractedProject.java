package com.securedeploy.upload.model;

import java.nio.file.Path;

public record ExtractedProject(
        String projectName,
        Path workspacePath,
        Path projectRoot
) {
}
