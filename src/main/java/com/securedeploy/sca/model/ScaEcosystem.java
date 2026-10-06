package com.securedeploy.sca.model;
public enum ScaEcosystem {
    MAVEN("Maven"), NPM("npm");
    private final String osvName;
    ScaEcosystem(String osvName) { this.osvName = osvName; }
    public String osvName() { return osvName; }
}
