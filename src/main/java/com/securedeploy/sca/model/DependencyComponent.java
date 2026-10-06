package com.securedeploy.sca.model;
public record DependencyComponent(
        ScaEcosystem ecosystem, String packageName, String version, String scope,
        Boolean direct, String sourceFile, int line, VersionResolution versionResolution
) {
    public String identity() { return ecosystem + "|" + packageName + "|" + version; }
}
