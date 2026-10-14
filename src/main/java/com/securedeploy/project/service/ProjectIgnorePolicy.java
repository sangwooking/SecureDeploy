package com.securedeploy.project.service;

import java.nio.file.Path;
import java.util.List;

public final class ProjectIgnorePolicy {
    public static final List<String> DIRECTORIES = List.of(
            "node_modules", ".git", "build", "dist", "target", "out", ".gradle", "coverage", "vendor");

    private ProjectIgnorePolicy() {}

    public static boolean ignores(Path relativePath) {
        for (Path segment : relativePath) {
            if (DIRECTORIES.contains(segment.toString())) return true;
        }
        return false;
    }
}
