package com.securedeploy.project.model;

import java.nio.file.Path;
import java.util.List;

public record ProjectFile(
        Path absolutePath,
        String relativePath,
        ProjectFileType type,
        List<String> lines
) {
}
