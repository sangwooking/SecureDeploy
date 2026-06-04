package com.securedeploy.upload.model;

import java.nio.file.Path;

public record UploadedArchive(
        String originalFileName,
        Path workspacePath,
        Path archivePath
) {
}
