package com.securedeploy.dependency.model;

/** Structured catalog provenance; a null advisoryId is a package-level candidate, not a CVE. */
public record DependencyObservation(String source, DependencyEcosystem ecosystem,
                                    String packageName, String version, String advisoryId) { }
