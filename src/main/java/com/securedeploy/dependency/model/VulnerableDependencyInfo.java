package com.securedeploy.dependency.model;

import com.securedeploy.rule.model.Severity;

public record VulnerableDependencyInfo(
        String dependencyName,
        String currentVersion,
        String safeVersion,
        DependencyEcosystem ecosystem,
        Severity severity,
        String cveId,
        String advisory,
        String recommendation
) {
}
