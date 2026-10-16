package com.securedeploy.project.model;

import java.nio.file.Path;
import java.util.List;

public record ProjectStructure(
        Path projectRoot,
        List<ProjectFile> analysisFiles,
        com.securedeploy.project.coverage.CoverageLedger coverage
) {
    public ProjectStructure(Path projectRoot, List<ProjectFile> analysisFiles) { this(projectRoot, analysisFiles, null); }
}
