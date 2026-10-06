package com.securedeploy.sca.service;

import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.ScaManifestCollector;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;

@Service
public class ScaService {
    private final ScaManifestCollector collector;
    private final VulnerabilityDataSource dataSource;
    private final ScaProperties properties;
    public ScaService(ScaManifestCollector collector, VulnerabilityDataSource dataSource, ScaProperties properties) {
        this.collector = collector;
        this.dataSource = dataSource;
        this.properties = properties;
    }
    public ScaResult analyze(ProjectStructure project) {
        if (!properties.enabled()) return result(ScaResult.Status.DISABLED, List.of(), List.of(), 0, List.of());
        ScaManifestCollector.Inventory inventory;
        try { inventory = collector.collect(project); }
        catch (RuntimeException exception) {
            return result(ScaResult.Status.UNAVAILABLE, List.of(), List.of(), 0, List.of("SCA manifest 분석을 완료하지 못했습니다."));
        }
        List<DependencyComponent> components = inventory.components();
        List<String> warnings = new ArrayList<>(inventory.warnings());
        if (inventory.manifestCount() == 0) return result(ScaResult.Status.NO_MANIFEST, components, List.of(), 0, warnings);
        List<DependencyComponent> exact = components.stream().filter(c -> c.versionResolution() == VersionResolution.EXACT).toList();
        boolean unresolved = components.stream().anyMatch(c -> c.versionResolution() != VersionResolution.EXACT);
        if (unresolved) warnings.add("범위/동적/누락 버전은 OSV에 조회하지 않았습니다. 미해결 의존성을 확인해 주세요.");
        try {
            VulnerabilityDataSource.LookupResult lookup = exact.isEmpty()
                    ? new VulnerabilityDataSource.LookupResult(List.of(), Set.of(), false, List.of()) : dataSource.lookup(exact);
            warnings.addAll(lookup.warnings());
            ScaResult.Status status = lookup.incomplete() && lookup.analyzedIdentities().isEmpty() && lookup.findings().isEmpty()
                    ? ScaResult.Status.UNAVAILABLE
                    : (!warnings.isEmpty() || lookup.incomplete() || unresolved ? ScaResult.Status.PARTIAL : ScaResult.Status.COMPLETE);
            return result(status, components, lookup.findings(), lookup.analyzedIdentities().size(), warnings);
        } catch (RuntimeException exception) {
            warnings.add("OSV 서비스를 사용할 수 없어 SCA 조회를 완료하지 못했습니다.");
            return result(ScaResult.Status.UNAVAILABLE, components, List.of(), 0, warnings);
        }
    }
    private ScaResult result(ScaResult.Status status, List<DependencyComponent> components,
                             List<DependencyVulnerability> findings, int analyzed, List<String> warnings) {
        Map<String, Long> severities = new LinkedHashMap<>();
        for (String severity : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")) severities.put(severity, 0L);
        findings.forEach(f -> severities.merge(f.severity() == null ? "UNKNOWN" : f.severity().name(), 1L, Long::sum));
        int discovered = (int) components.stream().map(DependencyComponent::identity).distinct().count();
        int unresolved = (int) components.stream().filter(c -> c.versionResolution() != VersionResolution.EXACT)
                .map(DependencyComponent::identity).distinct().count();
        int vulnerable = (int) findings.stream().map(f -> f.ecosystem() + "|" + f.packageName() + "|" + f.installedVersion()).distinct().count();
        return new ScaResult(1, status, Instant.now(), new ScaResult.Summary(discovered, analyzed, unresolved,
                vulnerable, findings.size(), severities), components, findings, List.copyOf(warnings));
    }
}
