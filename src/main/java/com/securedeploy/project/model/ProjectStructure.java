package com.securedeploy.project.model;

import java.nio.file.Path;
import java.util.List;

public record ProjectStructure(
        Path projectRoot,
        List<ProjectFile> analysisFiles,
        com.securedeploy.project.coverage.CoverageLedger coverage,
        java.util.Set<String> enumeratedDirectories
) {
    public ProjectStructure(Path root, List<ProjectFile> files, com.securedeploy.project.coverage.CoverageLedger coverage) {
        this(root, files, coverage, java.util.Set.of());
    }
    public ProjectStructure(Path projectRoot, List<ProjectFile> analysisFiles) { this(projectRoot, analysisFiles, null); }
}
