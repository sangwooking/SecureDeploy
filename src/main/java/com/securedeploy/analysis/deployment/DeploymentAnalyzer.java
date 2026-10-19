package com.securedeploy.analysis.deployment;

import com.securedeploy.project.model.*;
import com.securedeploy.project.coverage.CoverageRecorder;
import java.util.*;

public final class DeploymentAnalyzer {
    private DeploymentAnalyzer() { }
    public static DeploymentSnapshot analyze(ProjectStructure project, DeploymentSnapshot python) {
        var files = new ArrayList<DeploymentSnapshot.FileResult>();
        if (python != null) files.addAll(python.files());
        int parsed = 0, omitted = 0;
        long chars = 0, deadline = System.nanoTime() + 2_000_000_000L;
        for (var file : project.analysisFiles().stream().sorted(Comparator.comparing(ProjectFile::relativePath)).toList()) {
            if (file.type() != ProjectFileType.DOCKER_COMPOSE && file.type() != ProjectFileType.CLOUDFLARE_CONFIG) continue;
            long length = file.lines().stream().mapToLong(s -> s.length() + 1L).sum();
            String path = CoverageRecorder.safePath(file.relativePath());
            if (++parsed > 50 || chars + length > 1_000_000 || System.nanoTime() > deadline || path.equals("[redacted-path]")) {
                omitted++;
                if (omitted <= 50) files.add(new DeploymentSnapshot.FileResult(path, file.type().name(), "LIMIT_EXCEEDED", List.of(), List.of("CONFIG_RESOURCE_OR_PATH_LIMIT")));
                continue;
            }
            chars += length;
            files.add(file.type() == ProjectFileType.DOCKER_COMPOSE ? ComposeInspector.inspect(file) : WranglerInspector.inspect(file));
        }
        var limits = new ArrayList<>(List.of("DECLARATIONS_ONLY_RUNTIME_AND_OVERRIDES_UNKNOWN", "SUPPLEMENTAL_REVIEW_NOT_RISK_OR_SCORE"));
        if (omitted > 50) limits.add("OMITTED_CONFIG_DETAILS:" + (omitted - 50));
        if (python == null && project.analysisFiles().stream().anyMatch(f -> f.type() == ProjectFileType.PYTHON)) limits.add("DJANGO_SETTINGS_NOT_RUN");
        int candidates = files.stream().mapToInt(f -> (int) f.observations().stream().filter(o -> DeploymentGuidance.TEXT.containsKey(o.ruleId())).count()).sum();
        if (candidates > 300) limits.add("CONFIG_FINDING_LIMIT");
        return new DeploymentSnapshot(1, "deployment-v1", files.isEmpty() && !limits.contains("DJANGO_SETTINGS_NOT_RUN") ? "NOT_APPLICABLE" : "PARTIAL",
                List.copyOf(files), DeploymentGuidance.findings(files), List.copyOf(limits));
    }
}
