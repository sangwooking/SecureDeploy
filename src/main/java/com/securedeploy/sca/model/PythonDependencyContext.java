package com.securedeploy.sca.model;

import java.util.List;

/** Declaration evidence only. Does not claim installation, transitive closure, or runtime use. */
public record PythonDependencyContext(int schemaVersion, String rootManifest, String environment,
        String versionOrigin, String declaration, List<String> extras, String markerStatus,
        List<String> markerVariables, List<Location> constraints, List<String> limitations) {
    public record Location(String file, int line) { }
}
