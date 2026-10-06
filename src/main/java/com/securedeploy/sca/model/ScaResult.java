package com.securedeploy.sca.model;
import java.time.Instant;
import java.util.List;
import java.util.Map;
public record ScaResult(
        int schemaVersion,
        Status status, Instant analyzedAt, Summary summary, List<DependencyComponent> components,
        List<DependencyVulnerability> dependencyVulnerabilities, List<String> warnings
) {
    public enum Status { COMPLETE, PARTIAL, UNAVAILABLE, NO_MANIFEST, DISABLED }
    public record Summary(int dependenciesDiscovered, int dependenciesAnalyzed,
                          int unresolvedDependencies, int vulnerableDependencies,
                          int dependencyVulnerabilities, Map<String, Long> severityCounts) { }
}
