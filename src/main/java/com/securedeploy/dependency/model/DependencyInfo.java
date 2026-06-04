package com.securedeploy.dependency.model;

public record DependencyInfo(
        String name,
        String version,
        DependencyEcosystem ecosystem,
        String sourceFile,
        int line
) {
}
