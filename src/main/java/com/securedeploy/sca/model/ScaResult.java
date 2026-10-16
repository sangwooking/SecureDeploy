package com.securedeploy.sca.model;
import java.time.Instant;
import java.util.List;
import java.util.Map;
public record ScaResult(
        int schemaVersion,
        Status status, Instant analyzedAt, Summary summary, List<DependencyComponent> components,
        List<DependencyVulnerability> dependencyVulnerabilities, List<String> warnings,
        List<ManifestObservation> manifests
) {
    public ScaResult(int schemaVersion, Status status, Instant analyzedAt, Summary summary,
            List<DependencyComponent> components, List<DependencyVulnerability> dependencyVulnerabilities, List<String> warnings) {
        this(schemaVersion, status, analyzedAt, summary, components, dependencyVulnerabilities, warnings, null);
    }
    public ScaResult withManifests(List<ManifestObservation> observations) {
        return new ScaResult(2, status, analyzedAt, summary, components, dependencyVulnerabilities, warnings, List.copyOf(observations));
    }
    public enum Status { COMPLETE, PARTIAL, UNAVAILABLE, NO_MANIFEST, DISABLED }
    public record Summary(int dependenciesDiscovered, int dependenciesAnalyzed,
                          int unresolvedDependencies, int vulnerableDependencies,
                          int dependencyVulnerabilities, Map<String, Long> severityCounts) { }
}
