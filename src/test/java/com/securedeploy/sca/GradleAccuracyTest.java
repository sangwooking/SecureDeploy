package com.securedeploy.sca;

import com.securedeploy.sca.parser.GradleManifestParser;
import com.securedeploy.sca.model.VersionResolution;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class GradleAccuracyTest {
    private final GradleManifestParser parser = new GradleManifestParser();

    @Test void settingsSimilarNamesCommentsAndStringContentsAreNotDependencies() {
        var result = parser.parse(ScaParserTest.file("mobile/build.gradle.kts", """
            android { compileSdk = vendor.compileSdkVersion
                compileOptions { sourceCompatibility = JavaVersion.VERSION_17 }
                apiLevel = 35
            }
            val help = "implementation('example:fake:1.0')"
            // runtimeOnly("example:comment:2.0")
            val documentation = '''compile 'example:multiline:1.0'
            implementation "example:not-code:2.0"'''
            configurations { compileOnly { extendsFrom(annotationProcessor) } }
            dependencyInjection { api("example:unrelated:1.0") }
            dependencies {
                compileOnly("example:annotation:1.2.3")
                testImplementation(libs.tests)
            }
            """));
        assertThat(result).hasSize(2);
        assertThat(result.get(0).packageName()).isEqualTo("example:annotation");
        assertThat(result.get(1).versionResolution()).isEqualTo(VersionResolution.UNRESOLVED);
    }

    @Test void declarationsAreTokenizedAcrossLinesAndMixedStatements() {
        var result = parser.parse(ScaParserTest.file("service/build.gradle", """
            dependencies {
                implementation(
                    "example:core:2.0.0"
                )
                api group: 'example', name: 'api', version: '3.0'
                runtimeOnly("example:dynamic:" + selectedVersion); testImplementation(libs.tests)
                compileOnly(group = "example", name = "annotations", version = "1.0")
                implementation platform("example:bom:4.0")
            }
            """));
        assertThat(result).hasSize(6);
        assertThat(result).filteredOn(d -> d.versionResolution() == VersionResolution.EXACT).hasSize(3);
        assertThat(result).filteredOn(d -> d.versionResolution() == VersionResolution.UNRESOLVED).hasSize(3);
        assertThat(result.get(0).line()).isEqualTo(2);
        assertThat(result.get(1).packageName()).isEqualTo("example:api");
        assertThat(result.get(4).packageName()).isEqualTo("example:annotations");
    }

    @Test void unknownExpressionsStayUnknownWithoutExecutingThem() {
        var result = parser.parse(ScaParserTest.file("nested/build.gradle.kts", """
            dependencies {
                implementation(resolveDependency())
                runtimeOnly("example:missing")
                testImplementation("example:tests:$version")
                add("customRuntime", libs.custom)
            }
            """));
        assertThat(result).hasSize(4).allMatch(d -> d.versionResolution() == VersionResolution.UNRESOLVED);
    }

    @Test void invalidOrOversizedManifestDoesNotAbortRulesOrBecomeSuccessfulSca() {
        var legacy = new com.securedeploy.dependency.parser.GradleDependencyParser();
        var collector = new com.securedeploy.sca.parser.ScaManifestCollector(new com.fasterxml.jackson.databind.ObjectMapper());
        for (var content : java.util.List.of("dependencies { implementation(\"unfinished", " ".repeat(2_000_001))) {
            var file = ScaParserTest.file("build.gradle", content);
            assertThatThrownBy(() -> parser.parse(file)).isInstanceOf(IllegalArgumentException.class);
            assertThat(legacy.parse(file)).isEmpty();
            var structure = new com.securedeploy.project.model.ProjectStructure(java.nio.file.Path.of("fixture"), java.util.List.of(file));
            var inventory = collector.collect(structure);
            assertThat(inventory.observations()).hasSize(1);
            assertThat(inventory.observations().get(0).status()).isIn("FAILED", "LIMIT_EXCEEDED");
            assertThat(inventory.warnings()).isNotEmpty();
        }
    }
}
