package com.securedeploy.dependency.advisory;

import static org.assertj.core.api.Assertions.assertThat;

import com.securedeploy.dependency.model.DependencyEcosystem;
import com.securedeploy.dependency.model.DependencyInfo;
import org.junit.jupiter.api.Test;

class VulnerableDependencyCatalogTest {

    private final VulnerableDependencyCatalog catalog = new VulnerableDependencyCatalog();

    @Test
    void detectsKnownVulnerableDependencyCandidates() {
        assertThat(catalog.findVulnerability(new DependencyInfo("lodash", "4.17.10", DependencyEcosystem.NPM, "package.json", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("minimist", "1.2.0", DependencyEcosystem.NPM, "package.json", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("axios", "0.20.0", DependencyEcosystem.NPM, "package.json", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("serialize-javascript", "2.1.2", DependencyEcosystem.NPM, "package.json", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("org.apache.logging.log4j:log4j-core", "2.14.1", DependencyEcosystem.MAVEN, "pom.xml", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("com.fasterxml.jackson.core:jackson-databind", "2.9.10", DependencyEcosystem.MAVEN, "pom.xml", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("org.springframework:spring-webmvc", "5.3.10", DependencyEcosystem.GRADLE, "build.gradle", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("commons-collections:commons-collections", "3.2.1", DependencyEcosystem.GRADLE, "build.gradle", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("ubuntu", "18.04", DependencyEcosystem.DOCKER, "Dockerfile", 1))).isPresent();
        assertThat(catalog.findVulnerability(new DependencyInfo("node", "latest", DependencyEcosystem.DOCKER, "Dockerfile", 1))).isPresent();
    }

    @Test
    void ignoresSafeVersions() {
        assertThat(catalog.findVulnerability(new DependencyInfo("lodash", "4.17.21", DependencyEcosystem.NPM, "package.json", 1))).isEmpty();
        assertThat(catalog.findVulnerability(new DependencyInfo("org.apache.logging.log4j:log4j-core", "2.17.1", DependencyEcosystem.MAVEN, "pom.xml", 1))).isEmpty();
        assertThat(catalog.findVulnerability(new DependencyInfo("ubuntu", "22.04", DependencyEcosystem.DOCKER, "Dockerfile", 1))).isEmpty();
    }
}
