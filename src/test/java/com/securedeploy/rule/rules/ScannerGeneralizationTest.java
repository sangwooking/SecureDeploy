package com.securedeploy.rule.rules;

import com.securedeploy.project.model.*;
import com.securedeploy.sca.parser.GradleManifestParser;
import com.securedeploy.sca.model.VersionResolution;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static org.assertj.core.api.Assertions.*;

/** Separate synthetic variations; not a claim of real-world precision or a permanent blind holdout. */
class ScannerGeneralizationTest {
    record DockerCase(String source, DockerRuntimeUser.Status expected) { }
    static List<DockerCase> dockerCases() {
        var root = DockerRuntimeUser.Status.ROOT_DECLARED;
        var named = DockerRuntimeUser.Status.NON_ROOT_DECLARED;
        var unknown = DockerRuntimeUser.Status.UNKNOWN;
        return List.of(
            new DockerCase("FROM unrelated:2 AS Compile\nUSER 0:staff\nFROM Compile AS middle\nFROM middle AS release", root),
            new DockerCase("FROM unrelated:2\nuSeR root:worker", root),
            new DockerCase("FROM --platform=linux/amd64 unrelated:2\nUSER 000:1000", root),
            new DockerCase("FROM unrelated:2 AS compile\nUSER root\nFROM other:3 AS release\nUSER 2000:0", named),
            new DockerCase("FROM unrelated:2 AS a\nUSER application\nFROM a AS b\nFROM b", named),
            new DockerCase("# escape=`\nFROM unrelated:2\nUSER `\n  2000", named),
            new DockerCase("FROM unrelated:2\nCOPY <<'DOC' /fixture\nUSER root\nDOC\nUSER service", named),
            new DockerCase("FROM unrelated:2 AS a\nUSER root\nFROM ${BASE}", unknown),
            new DockerCase("FROM unrelated:2\nARG WHO=0\nUSER $WHO", unknown),
            new DockerCase("FROM unrelated:2 AS a\nUSER application\nONBUILD USER root\nFROM a", unknown)
        );
    }
    @ParameterizedTest @MethodSource("dockerCases")
    void classifiesDefaultRuntimeWithoutConvertingUnknownToSafe(DockerCase c) {
        var file = new ProjectFile(Path.of("Dockerfile"), "services/unrelated/Dockerfile", ProjectFileType.DOCKERFILE, c.source().lines().toList());
        assertThat(DockerRuntimeUser.inspect(file).status()).isEqualTo(c.expected());
        assertThat(new DockerRootUserRule().evaluate(file)).hasSize(c.expected() == DockerRuntimeUser.Status.ROOT_DECLARED ? 1 : 0);
    }
    record GradleCase(String source, int exact, int unknown) { }
    static List<GradleCase> gradleCases() {
        return List.of(
            new GradleCase("subprojects { dependencies { compileOnly 'acme:api:9.1' } }", 1, 0),
            new GradleCase("android { compileSdkVersion(35) }\nval runtimeVersion = 2\nval apiLevel = 3", 0, 0),
            new GradleCase("dependencies.api(\"acme:api:9.1\")", 1, 0),
            new GradleCase("dependencies { implementation(libs.catalog); runtimeOnly(resolveVersion()) }", 0, 2),
            new GradleCase("def documentation = \"\"\"runtimeOnly('acme:not-code:1.0')\napi('acme:note:1.0')\"\"\"", 0, 0),
            new GradleCase("dependencies { api group: 'acme', name: 'lib', version: selectedVersion }", 0, 1)
        );
    }
    @ParameterizedTest @MethodSource("gradleCases")
    void declarationVariationsDoNotDependOnRepositoryNames(GradleCase c) {
        var file = new ProjectFile(Path.of("build.gradle"), "unrelated/build.gradle", ProjectFileType.GRADLE_BUILD, c.source().lines().toList());
        var parsed = new GradleManifestParser().parse(file);
        assertThat(parsed).filteredOn(d -> d.versionResolution() == VersionResolution.EXACT).hasSize(c.exact());
        assertThat(parsed).filteredOn(d -> d.versionResolution() != VersionResolution.EXACT).hasSize(c.unknown());
    }
}
