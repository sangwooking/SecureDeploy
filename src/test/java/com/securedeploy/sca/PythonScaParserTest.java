package com.securedeploy.sca;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.*;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.assertj.core.api.Assertions.*;

class PythonScaParserTest {
    static PythonManifestParser.Inventory parse(String... pairs) {
        List<ProjectFile> files = new ArrayList<>();
        for (int i = 0; i < pairs.length; i += 2) files.add(ScaParserTest.file(pairs[i], pairs[i + 1]));
        return new PythonManifestParser().collect(files);
    }
    @ParameterizedTest @CsvSource({
        "Django==4.2.1, django, EXACT", "my_Package.name==1.2rc1, my-package-name, EXACT",
        "example==1!2.0.post1.dev2, example, EXACT", "example>=1.2, example, RANGE",
        "example==1.2.*, example, RANGE", "example~=1.2, example, RANGE",
        "example, example, UNRESOLVED", "example===private, example, UNRESOLVED",
        "example==1.0+local, example, UNRESOLVED", "example==01.0, example, UNRESOLVED",
        "example==garbage, example, UNRESOLVED", "example==${VERSION}, example, UNRESOLVED"
    }) void exactRangeAndUnknownAreDistinct(String input, String name, VersionResolution expected) {
        var r = PythonRequirement.parse(input);
        assertThat(r.name()).isEqualTo(name); assertThat(r.resolution()).isEqualTo(expected);
    }
    @Test void normalizesExtrasWithoutEvaluatingEnvironmentOrRetainingArbitraryMarkerValues() throws Exception {
        var result = parse("requirements-dev.txt", "Test_Pkg[Fast_IO]==1.2; (python_version >= '3.10' and sys_platform != 'example-sensitive-marker')\n");
        var c = result.components().get(0);
        assertThat(c.packageName()).isEqualTo("test-pkg");
        assertThat(c.python().extras()).containsExactly("fast-io");
        assertThat(c.python().markerVariables()).containsExactly("python_version", "sys_platform");
        assertThat(c.python().markerStatus()).isEqualTo("CONDITIONAL_NOT_EVALUATED");
        assertThat(c.scope()).isEqualTo("DEVELOPMENT_FILENAME_HINT");
        assertThat(result.warnings()).isNotEmpty();
        assertThat(new ObjectMapper().writeValueAsString(result)).doesNotContain("example-sensitive-marker");
    }
    @Test void markersThatCannotBeParsedAreUnresolvedNotIgnored() {
        for (var marker : List.of("", "python_version >=", "unknown_field == 'x'", "python_version == '3.9' unexpected", "__import__('os')")) {
            assertThat(PythonRequirement.parse("fixture==1.0; " + marker).resolution()).isEqualTo(VersionResolution.UNRESOLVED);
        }
    }
    @Test void includesAndConstraintsHaveDifferentMeaningsAndConstraintsNeverInstallPackages() {
        var result = parse("requirements-dev.txt", "-r requirements/base.txt\n-c constraints.txt\nfixture-dev==2.0\n",
                "requirements/base.txt", "fixture-main\n", "constraints.txt", "fixture-main==1.0\nfixture-unused==3.0\n");
        assertThat(result.components()).hasSize(2).noneMatch(c -> c.packageName().equals("fixture-unused"));
        var pinned = result.components().stream().filter(c -> c.packageName().equals("fixture-main")).findFirst().orElseThrow();
        assertThat(pinned.version()).isEqualTo("1.0");
        assertThat(pinned.python().versionOrigin()).isEqualTo("CONSTRAINT_PIN");
        assertThat(pinned.sourceFile()).isEqualTo("requirements/base.txt");
        assertThat(pinned.python().constraints().get(0).file()).isEqualTo("constraints.txt");
        assertThat(pinned.scope()).isEqualTo("DEVELOPMENT_FILENAME_HINT");
        assertThat(result.warnings()).isEmpty();
        var mixed = parse("requirements.txt", "-c constraints.txt\nfixture==1.0",
                "constraints.txt", "-r requirements-extra.txt", "requirements-extra.txt", "other==2.0");
        assertThat(mixed.warnings()).anyMatch(w -> w.contains("REQUIREMENT_FROM_CONSTRAINT_UNSUPPORTED"));
    }
    @Test void conflictsAndConstraintRangesNeverInventASelectedVersion() {
        var conflict = parse("requirements.txt", "Fixture==1.0\nfixture==2.0\n");
        assertThat(conflict.components()).hasSize(2).allMatch(c -> c.versionResolution() == VersionResolution.UNRESOLVED);
        assertThat(conflict.warnings()).isNotEmpty();
        var range = parse("requirements.txt", "-c constraints.txt\nfixture>=1.0\n", "constraints.txt", "fixture==2.0");
        assertThat(range.components()).hasSize(1).allMatch(c -> c.versionResolution() == VersionResolution.UNRESOLVED);
        var conflictWithBare = parse("requirements.txt", "fixture\nfixture==1.0\n-c constraints.txt", "constraints.txt", "fixture==2.0");
        assertThat(conflictWithBare.components()).hasSize(2).allMatch(c -> c.versionResolution() == VersionResolution.UNRESOLVED);
        var duplicates = parse("requirements.txt", "Fixture==1.0\nfixture==1.0");
        assertThat(duplicates.components()).hasSize(2).allMatch(c -> c.versionResolution() == VersionResolution.EXACT);
        assertThat(duplicates.components().stream().map(DependencyComponent::identity).distinct()).hasSize(1);
        assertThat(duplicates.components()).allMatch(c -> c.direct() == null);
    }
    @Test void separateRootEnvironmentsDoNotBecomeFalseVersionConflicts() {
        var result = parse("requirements-dev.txt", "fixture==1.0", "requirements-prod.txt", "fixture==2.0");
        assertThat(result.components()).hasSize(2).allMatch(c -> c.versionResolution() == VersionResolution.EXACT);
        assertThat(result.warnings()).isEmpty();
    }
    @Test void traversalCyclesMissingSymlinksAndRemoteIncludesDoNotReadOutsideInventory() {
        for (var reference : List.of("../../requirements.txt", "/etc/requirements.txt", "https://example.invalid/requirements.txt", "requirements-missing.txt")) {
            var r = parse("requirements.txt", "-r " + reference + "\nfixture==1.0");
            assertThat(r.observations().get(0).status()).isEqualTo("PARTIAL");
            assertThat(r.warnings().toString()).doesNotContain("https://", "/etc/", "../../");
        }
        var cycle = parse("requirements.txt", "-r requirements-dev.txt", "requirements-dev.txt", "-r requirements.txt");
        assertThat(cycle.warnings()).anyMatch(w -> w.contains("CYCLIC"));
        assertThat(cycle.components()).isEmpty();
    }
    @Test void localGitUrlEditableAndCustomIndexesAreNotPyPiProofAndSecretsAreDiscarded() throws Exception {
        var result = parse("requirements.txt", """
            fixture @ git+https://synthetic-user:synthetic-secret@example.invalid/repo
            git+https://synthetic-user:synthetic-secret@example.invalid/repo
            ./private-package
            -e ./private-package
            --index-url https://synthetic-user:synthetic-secret@example.invalid/simple
            actual-name==1.0
            """);
        assertThat(result.components()).hasSize(5).allMatch(c -> c.versionResolution() == VersionResolution.UNRESOLVED);
        assertThat(new ObjectMapper().writeValueAsString(result)).doesNotContain("synthetic-secret", "synthetic-user", "example.invalid", "private-package");
        assertThat(result.components()).noneMatch(c -> c.packageName().equals("git") || c.packageName().equals("https"));
    }
    @Test void multilineHashesAndCommentsAreStaticNoArtifactHashesArePersisted() {
        var result = parse("requirements.txt", "# note\nfixture==1.0 \\\n  --hash=sha256:0123456789abcdef # not a version\n");
        assertThat(result.components()).hasSize(1).allMatch(c -> c.versionResolution() == VersionResolution.EXACT);
        assertThat(result.components().get(0).line()).isEqualTo(2);
    }
    @Test void standardTomlArraysAreParsedWithLocationsAndDistinctDeclarationScopes() {
        var result = parse("pyproject.toml", """
            [project]
            name = "fixture"
            dependencies = [
              "fixture-lib==1.2.3",
              "fixture-range>=2.0",
            ]
            [project.optional-dependencies]
            web = ["fixture-web[fast]==3.0"]
            [dependency-groups]
            test = ["fixture-test==4.0"]
            [build-system]
            requires = ["fixture-build==5.0"]
            """);
        assertThat(result.components()).hasSize(5);
        assertThat(result.components().get(0).line()).isEqualTo(3); // TOML parser position starts at the array's value region.
        assertThat(result.components()).extracting(DependencyComponent::scope).contains("PROJECT_DECLARATION", "BUILD_DECLARATION", "OPTIONAL_DECLARATION", "DEVELOPMENT_GROUP_DECLARATION");
    }
    @Test void invalidDynamicAndToolSpecificTomlAreNeverEmptySuccess() {
        assertThat(parse("pyproject.toml", "[project\ndependencies = [").observations().get(0).status()).isEqualTo("FAILED");
        for (var source : List.of("[project]\ndynamic=['dependencies']", "[tool.poetry.dependencies]\nfixture='1.0'",
                "[project]\ndependencies=['fixture==1.0']\n[tool.uv.sources]\nfixture={path='../x'}",
                "[dependency-groups]\ntest=[{include-group='other'}]")) {
            var result = parse("pyproject.toml", source);
            assertThat(result.warnings()).isNotEmpty();
            assertThat(result.components()).isNotEmpty().allMatch(c -> c.versionResolution() == VersionResolution.UNRESOLVED);
        }
    }
    @Test void unsupportedLocksAndSizeLimitsHaveExplicitStatuses() {
        for (var name : List.of("poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock", "pylock.toml", "setup.cfg")) {
            var result = parse(name, "arbitrary data");
            assertThat(result.observations().get(0).status()).isEqualTo("UNSUPPORTED");
            assertThat(result.components()).isEmpty(); assertThat(result.warnings()).isNotEmpty();
        }
        assertThat(parse("requirements.txt", " ".repeat(200_001)).observations().get(0).status()).isEqualTo("LIMIT_EXCEEDED");
        assertThat(parse("pyproject.toml", "[".repeat(300)).observations().get(0).status()).isEqualTo("LIMIT_EXCEEDED");
    }
    @Test void collectsKnownManifestTypesAndPythonSourceForItsSeparateAnalyzer() {
        var collector = new ProjectFileCollector();
        for (var name : List.of("backend/requirements.txt", "requirements-production.txt", "requirements/base.txt", "constraints.txt", "pyproject.toml", "uv.lock")) assertThat(collector.resolveAnalysisFileType(Path.of(name))).isPresent();
        assertThat(collector.resolveAnalysisFileType(Path.of("server.py"))).contains(ProjectFileType.PYTHON);
        assertThat(collector.resolveAnalysisFileType(Path.of("notes.txt"))).isEmpty();
    }
}
