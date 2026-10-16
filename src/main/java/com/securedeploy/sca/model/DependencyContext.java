package com.securedeploy.sca.model;

import java.util.List;

/** Declared installation paths are not runtime reachability evidence. */
public record DependencyContext(int schemaVersion, String environment, String runtimeReachability,
        String installedPath, int lockLine, List<String> lockFlags, boolean pathsComplete,
        List<DependencyPath> paths, List<String> limitations) {
    public record DependencyPath(String declarationFile, int declarationLine, String declarationSection,
            String declaredPackage, String declaredVersion, boolean declarationConfirmed,
            boolean optional, boolean peer, List<Hop> chain) { }
    public record Hop(String packageName, String version, String installedPath) { }
}
