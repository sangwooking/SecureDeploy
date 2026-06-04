package com.securedeploy.project.model;

import java.nio.file.Path;
import java.util.List;

public record ProjectStructure(
        Path projectRoot,
        List<ProjectFile> analysisFiles
) {
}
