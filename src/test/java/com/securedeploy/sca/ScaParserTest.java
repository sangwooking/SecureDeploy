package com.securedeploy.sca;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.*;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ScaParserTest {
    private final ObjectMapper mapper = new ObjectMapper();
    static ProjectFile file(String path, String content) {
        return new ProjectFile(Path.of(path), path, new ProjectFileCollector().resolveAnalysisFileType(Path.of(path)).orElseThrow(),
                content.lines().toList());
    }
    static ProjectFile fixture(String name) throws Exception {
        return file(name, Files.readString(Path.of(ScaParserTest.class.getResource("/sca/" + name).toURI())));
    }
    @Test void mavenUsesLocalPropertiesAndDoesNotInventManagedVersions() throws Exception {
        var dependencies = new MavenManifestParser().parse(fixture("pom.xml"));
        assertThat(dependencies).hasSize(2);
        assertThat(dependencies.get(0).packageName()).isEqualTo("org.apache.logging.log4j:log4j-core");
        assertThat(dependencies.get(0).version()).isEqualTo("2.14.1");
        assertThat(dependencies.get(0).scope()).isEqualTo("runtime");
        assertThat(dependencies.get(1).versionResolution()).isEqualTo(VersionResolution.UNRESOLVED);
    }
    @Test void rejectsDtdAndExternalEntities() {
        var xml = file("pom.xml", "<!DOCTYPE project [<!ENTITY xxe SYSTEM 'file:///not-readable'>]><project>&xxe;</project>");
        assertThatThrownBy(() -> new MavenManifestParser().parse(xml)).isInstanceOf(Exception.class);
    }
    @Test void gradleHandlesGroovyKotlinMapAndUnresolvedExpressions() throws Exception {
        var dependencies = new GradleManifestParser().parse(fixture("build.gradle"));
        assertThat(dependencies).hasSize(5);
        assertThat(dependencies).filteredOn(d -> d.versionResolution() == VersionResolution.EXACT).hasSize(3);
        assertThat(dependencies).filteredOn(d -> d.versionResolution() == VersionResolution.UNRESOLVED).hasSize(2);
        var kotlin = new GradleManifestParser().parse(file("build.gradle.kts",
                "/* implementation(\"fake:comment:1.0\") */\nruntimeOnly(\"test.fixture:kotlin:1.0.0\")"));
        assertThat(kotlin).hasSize(1);
        assertThat(kotlin.get(0).versionResolution()).isEqualTo(VersionResolution.EXACT);
    }
    @Test void npmLockIncludesTransitiveAndHandlesBothLockFormats() throws Exception {
        var parser = new NpmManifestParser(mapper);
        for (int version : List.of(2, 3)) {
            var lock = fixture("package-lock.json");
            var items = parser.parseLock(file("package-lock.json", String.join("\n", lock.lines()).replace("\"lockfileVersion\": 3", "\"lockfileVersion\": " + version)));
            assertThat(items).hasSize(3);
            assertThat(items.get(0).direct()).isTrue();
            assertThat(items.get(1).direct()).isFalse();
            assertThat(items.get(1).scope()).isEqualTo("devDependencies");
        }
    }
    @Test void rangesAreNeverQueriedAndUrlCredentialsAreNeverRetained() throws Exception {
        for (String version : List.of("^1.2.3", "~1.2.3", ">1.2.3", "*", "latest", "workspace:*", "1.x", "git+https://fake:fake@example.invalid/pkg")) {
            var d = VersionClassifier.component(ScaEcosystem.NPM, "pkg", version, "dependencies", true, "package.json", 0);
            assertThat(d.versionResolution()).isNotEqualTo(VersionResolution.EXACT);
            assertThat(d.version()).doesNotContain("fake:fake");
        }
        var literal = new NpmManifestParser(mapper).parseManifest(file("package.json", "{\"dependencies\":{\"lodash\":\"4.17.21\"}}"));
        assertThat(literal.get(0).versionResolution()).isEqualTo(VersionResolution.EXACT);
    }
    @Test void collectorPrefersLocksWithinTheirModule() throws Exception {
        var collector = new ScaManifestCollector(mapper);
        var result = collector.collect(new ProjectStructure(Path.of("."), List.of(fixture("package.json"),
                fixture("package-lock.json"), fixture("build.gradle"), fixture("gradle.lockfile"))));
        assertThat(result.components()).anySatisfy(c -> {
            assertThat(c.packageName()).isEqualTo("lodash");
            assertThat(c.version()).isEqualTo("4.17.10");
        });
        assertThat(result.components()).noneMatch(c -> "5.3.10".equals(c.version()));
        assertThat(result.components()).anyMatch(c -> "5.3.20".equals(c.version()) && c.sourceFile().equals("build.gradle"));
        assertThat(result.components()).anyMatch(c -> "unknown-version".equals(c.packageName()) && c.versionResolution() == VersionResolution.UNRESOLVED);
    }
    @Test void malformedLockIsPartialAndDoesNotFallBackToDeclaredInstalledVersion() {
        var collector = new ScaManifestCollector(mapper);
        var result = collector.collect(new ProjectStructure(Path.of("."), List.of(file("package-lock.json", "{bad"),
                file("package.json", "{\"dependencies\":{\"lodash\":\"4.17.10\"}}"))));
        assertThat(result.warnings()).isNotEmpty();
        assertThat(result.components()).allMatch(c -> c.versionResolution() == VersionResolution.UNRESOLVED);
    }

    @Test void npmAliasUsesActualPackageAndNonRegistryEntriesStayUnresolved() throws Exception {
        var items = new NpmManifestParser(mapper).parseLock(file("package-lock.json", """
            {"lockfileVersion":3,"packages":{
              "":{"dependencies":{"alias":"npm:lodash@^4.17.0","custom":"https://example.invalid/custom.tgz"}},
              "node_modules/alias":{"version":"4.17.10"},
              "node_modules/custom":{"version":"1.0.0","resolved":"https://example.invalid/custom.tgz"}
            }}
            """));
        assertThat(items).anyMatch(c -> c.packageName().equals("lodash") && c.versionResolution() == VersionResolution.EXACT && c.direct());
        assertThat(items).anyMatch(c -> c.packageName().equals("custom") && c.versionResolution() == VersionResolution.UNRESOLVED);
    }

    @Test void incompleteLockAndInvalidSemverNeverBecomeExact() throws Exception {
        var items = new NpmManifestParser(mapper).parseLock(file("package-lock.json", """
            {"lockfileVersion":3,"packages":{"":{"dependencies":{"missing":"1.0.0"}}}}
            """));
        assertThat(items).hasSize(1);
        assertThat(items.get(0).versionResolution()).isEqualTo(VersionResolution.UNRESOLVED);
        for (String version : List.of("1.2.3-01", "1.2.3-alpha..1", "1.2.3+build..1")) {
            assertThat(VersionClassifier.classify(ScaEcosystem.NPM, version)).isNotEqualTo(VersionResolution.EXACT);
        }
        assertThat(VersionClassifier.classify(ScaEcosystem.NPM, "1.2.3-alpha.1+build.01")).isEqualTo(VersionResolution.EXACT);
    }

    @Test void concatenatedGradleVersionAndMissingMavenCoordinatesStayUnresolved() throws Exception {
        var gradle = new GradleManifestParser().parse(file("build.gradle", "implementation 'example:lib:1.0' + suffix"));
        assertThat(gradle.get(0).versionResolution()).isEqualTo(VersionResolution.UNRESOLVED);
        var maven = new MavenManifestParser().parse(file("pom.xml",
                "<project><dependencies><dependency><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>"));
        assertThat(maven.get(0).versionResolution()).isEqualTo(VersionResolution.UNRESOLVED);
    }
}
