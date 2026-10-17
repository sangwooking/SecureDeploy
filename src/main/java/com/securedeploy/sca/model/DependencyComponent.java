package com.securedeploy.sca.model;
public record DependencyComponent(
        ScaEcosystem ecosystem, String packageName, String version, String scope,
        Boolean direct, String sourceFile, int line, VersionResolution versionResolution,
        DependencyContext context, PythonDependencyContext python
) {
    public DependencyComponent(ScaEcosystem ecosystem, String packageName, String version, String scope,
            Boolean direct, String sourceFile, int line, VersionResolution versionResolution, DependencyContext context) {
        this(ecosystem, packageName, version, scope, direct, sourceFile, line, versionResolution, context, null);
    }
    public DependencyComponent(ScaEcosystem ecosystem, String packageName, String version, String scope,
            Boolean direct, String sourceFile, int line, VersionResolution versionResolution) {
        this(ecosystem, packageName, version, scope, direct, sourceFile, line, versionResolution, null);
    }
    public DependencyComponent withContext(DependencyContext value, int sourceLine) {
        return new DependencyComponent(ecosystem, packageName, version, scope, direct, sourceFile, sourceLine, versionResolution, value, python);
    }
    public String identity() { return ecosystem + "|" + packageName + "|" + version; }
}
