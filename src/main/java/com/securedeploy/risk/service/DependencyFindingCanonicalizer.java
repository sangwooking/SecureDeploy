package com.securedeploy.risk.service;

import com.securedeploy.sca.model.DependencyVulnerability;
import com.securedeploy.sca.model.ScaEcosystem;
import java.util.*;

/** Joins advisories only through explicit shared identifiers within the same package/version. */
public final class DependencyFindingCanonicalizer {
    private record Coordinate(ScaEcosystem ecosystem, String name, String version) { }
    private static final class Group {
        final Set<String> ids = new TreeSet<>();
        final List<DependencyVulnerability> findings = new ArrayList<>();
    }

    public List<DependencyVulnerability> canonicalize(List<DependencyVulnerability> findings) {
        Map<Coordinate, List<Group>> packages = new LinkedHashMap<>();
        for (var finding : findings) {
            var coordinate = new Coordinate(finding.ecosystem(), finding.packageName(), finding.installedVersion());
            var groups = packages.computeIfAbsent(coordinate, key -> new ArrayList<>());
            Group combined = new Group();
            combined.ids.add(normalizeId(finding.osvId()));
            finding.aliases().stream().filter(Objects::nonNull).filter(id -> !id.isBlank())
                    .map(DependencyFindingCanonicalizer::normalizeId).forEach(combined.ids::add);
            combined.findings.add(finding);
            // A later alias can bridge two earlier provider records of the same advisory.
            for (var iterator = groups.iterator(); iterator.hasNext();) {
                Group existing = iterator.next();
                if (!Collections.disjoint(combined.ids, existing.ids)) {
                    combined.ids.addAll(existing.ids);
                    combined.findings.addAll(existing.findings);
                    iterator.remove();
                }
            }
            groups.add(combined);
        }
        return packages.values().stream().flatMap(List::stream).map(this::merge)
                .sorted(Comparator.comparing(DependencyFindingCanonicalizer::identity)).toList();
    }

    public static String normalizeId(String id) { return id.strip().toUpperCase(Locale.ROOT); }
    public static String identity(DependencyVulnerability f) {
        return "dependency:" + f.ecosystem() + "|" + f.packageName() + "|" + f.installedVersion() + "|" + f.osvId();
    }

    private DependencyVulnerability merge(Group group) {
        var first = group.findings.get(0);
        String canonical = group.ids.stream().filter(id -> id.startsWith("CVE-")).findFirst()
                .orElseGet(() -> group.ids.stream().filter(id -> id.startsWith("GHSA-")).findFirst().orElse(group.ids.iterator().next()));
        var severity = group.findings.stream().map(DependencyVulnerability::severity).filter(Objects::nonNull)
                .max(Comparator.naturalOrder()).orElse(null);
        Double score = group.findings.stream().map(DependencyVulnerability::cvssScore).filter(Objects::nonNull)
                .filter(v -> Double.isFinite(v) && v >= 0 && v <= 10).max(Double::compare).orElse(null);
        return new DependencyVulnerability(first.ecosystem(), first.packageName(), first.installedVersion(), canonical,
                List.copyOf(group.ids), group.findings.stream().map(DependencyVulnerability::summary).filter(Objects::nonNull)
                .distinct().sorted().collect(java.util.stream.Collectors.joining("\n")), severity, score,
                union(group, DependencyVulnerability::cvssVectors), union(group, DependencyVulnerability::fixedVersions),
                group.findings.stream().map(DependencyVulnerability::published).filter(Objects::nonNull).min(String::compareTo).orElse(null),
                group.findings.stream().map(DependencyVulnerability::modified).filter(Objects::nonNull).max(String::compareTo).orElse(null),
                union(group, DependencyVulnerability::referenceUrls), union(group, DependencyVulnerability::sourceFiles));
    }

    private List<String> union(Group group, java.util.function.Function<DependencyVulnerability, List<String>> field) {
        return group.findings.stream().flatMap(f -> field.apply(f).stream()).distinct().sorted().toList();
    }
}
