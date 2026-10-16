package com.securedeploy.sca;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.sca.parser.NpmManifestParser;
import com.securedeploy.sca.model.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class NpmDependencyContextTest {
    private final NpmManifestParser parser = new NpmManifestParser(new ObjectMapper());
    private List<DependencyComponent> parse(String root, String packages) throws Exception {
        var manifest = ScaParserTest.file("package.json", root);
        var lock = ScaParserTest.file("package-lock.json", "{\"lockfileVersion\":3,\"packages\":{\"\":" + root + "," + packages + "}}");
        return parser.parseLock(lock, List.of(manifest));
    }
    @Test void preservesSharedRoutesAndDeclarationAndLockLocationsWithoutClaimingReachability() throws Exception {
        var items = parse("{\"dependencies\":{\"app-lib\":\"1.0.0\"},\"devDependencies\":{\"test-tool\":\"2.0.0\"}}", """
            "node_modules/app-lib":{"version":"1.0.0","dependencies":{"leaf":"3.0.0"}},
            "node_modules/test-tool":{"version":"2.0.0","dev":true,"dependencies":{"leaf":"3.0.0"}},
            "node_modules/leaf":{"version":"3.0.0","devOptional":true}
            """);
        var leaf = items.stream().filter(c -> c.packageName().equals("leaf")).findFirst().orElseThrow();
        assertThat(leaf.direct()).isFalse();
        assertThat(leaf.context().environment()).isEqualTo("SHARED");
        assertThat(leaf.context().runtimeReachability()).isEqualTo("NOT_ANALYZED");
        assertThat(leaf.context().paths()).hasSize(2).allSatisfy(path -> {
            assertThat(path.declarationFile()).isEqualTo("package.json");
            assertThat(path.declarationLine()).isEqualTo(1);
            assertThat(path.declarationConfirmed()).isTrue();
            assertThat(path.chain()).hasSize(2);
        });
        assertThat(leaf.context().lockFlags()).contains("devOptional");
        assertThat(leaf.line()).isPositive();
        assertThat(items.get(0).context().environment()).isEqualTo("PRODUCTION");
        assertThat(items.get(1).context().environment()).isEqualTo("DEVELOPMENT");
    }
    @Test void optionalPeerMissingRootAndContradictoryDevFlagsDoNotInventProductionReachability() throws Exception {
        var items = parse("{\"optionalDependencies\":{\"optional-lib\":\"1.0.0\"},\"peerDependencies\":{\"peer\":\"1.0.0\"},\"dependencies\":{\"contradiction\":\"1.0.0\"}}", """
            "node_modules/optional-lib":{"version":"1.0.0","optional":true},
            "node_modules/peer":{"version":"1.0.0"},
            "node_modules/contradiction":{"version":"1.0.0","dev":true},
            "node_modules/orphan":{"version":"1.0.0","dev":true}
            """);
        assertThat(items.get(0).context().paths().get(0).optional()).isTrue();
        assertThat(items.get(0).context().environment()).isEqualTo("PRODUCTION");
        assertThat(items.subList(1, 4)).allSatisfy(c -> assertThat(c.context().environment()).isEqualTo("UNKNOWN"));
    }
    @Test void nearestNestedVersionCyclesAndMultipleDirectParentsAreRetained() throws Exception {
        var items = parse("{\"devDependencies\":{\"tool\":\"1.0.0\"},\"dependencies\":{\"leaf\":\"2.0.0\"}}", """
            "node_modules/tool":{"version":"1.0.0","dev":true,"dependencies":{"leaf":"1.0.0"}},
            "node_modules/tool/node_modules/leaf":{"version":"1.0.0","dev":true,"dependencies":{"tool":"1.0.0"}},
            "node_modules/leaf":{"version":"2.0.0"}
            """);
        assertThat(items.get(1).context().environment()).isEqualTo("DEVELOPMENT");
        assertThat(items.get(1).context().paths().get(0).chain().get(0).packageName()).isEqualTo("tool");
        assertThat(items.get(2).context().environment()).isEqualTo("PRODUCTION");
    }
    @Test void staleManifestUnresolvedVersionAndCredentialSpecsStayUnknownOrRedacted() throws Exception {
        var lock = ScaParserTest.file("package-lock.json", """
            {"lockfileVersion":3,"packages":{"":{"devDependencies":{"tool":"git+https://synthetic:synthetic@example.invalid/tool"}},
              "node_modules/tool":{"version":"1.0.0","resolved":"https://example.invalid/tool"}}}
            """);
        var item = parser.parseLock(lock, List.of(ScaParserTest.file("package.json", "{\"dependencies\":{\"tool\":\"2.0.0\"}}"))).get(0);
        assertThat(item.versionResolution()).isEqualTo(VersionResolution.UNRESOLVED);
        assertThat(item.context().environment()).isEqualTo("UNKNOWN");
        assertThat(new ObjectMapper().writeValueAsString(item)).doesNotContain("synthetic", "https://");
        var old = new ObjectMapper().readValue("{\"ecosystem\":\"NPM\",\"packageName\":\"leaf\",\"version\":\"1.0.0\",\"line\":0}", DependencyComponent.class);
        assertThat(old.context()).isNull();
    }
    @Test void traversalLimitDoesNotSilentlyDiscardRoutesAndClaimDevelopmentOnly() throws Exception {
        var root = new StringBuilder("{\"devDependencies\":{");
        var packages = new StringBuilder();
        for (int i = 0; i < 14; i++) {
            if (i > 0) { root.append(','); packages.append(','); }
            root.append("\"tool").append(i).append("\":\"1.0.0\"");
            packages.append("\"node_modules/tool").append(i).append("\":{\"version\":\"1.0.0\",\"dependencies\":{\"leaf\":\"1.0.0\"}}");
        }
        root.append("}}"); packages.append(",\"node_modules/leaf\":{\"version\":\"1.0.0\"}");
        var leaf = parse(root.toString(), packages.toString()).stream().filter(c -> c.packageName().equals("leaf")).findFirst().orElseThrow();
        assertThat(leaf.context().paths()).hasSize(12);
        assertThat(leaf.context().pathsComplete()).isFalse();
        assertThat(leaf.context().environment()).isEqualTo("UNKNOWN");
        assertThat(parse(root.toString(), packages.toString()).stream().filter(c -> c.packageName().equals("tool0")).findFirst().orElseThrow()
                .context().environment()).isEqualTo("DEVELOPMENT");
    }

    @Test void aliasWorkspaceLinkAndManifestOnlyDeclareWhatWasActuallyObserved() throws Exception {
        var items = parse("{\"devDependencies\":{\"alias\":\"npm:fixture-leaf@1.0.0\",\"workspace\":\"workspace:*\"}}", """
            "node_modules/alias":{"version":"1.0.0","dev":true},
            "node_modules/workspace":{"link":true,"resolved":"packages/workspace"}
            """);
        assertThat(items.get(0).context().paths().get(0).declaredPackage()).isEqualTo("alias");
        assertThat(items.get(0).context().paths().get(0).chain().get(0).packageName()).isEqualTo("fixture-leaf");
        assertThat(items.get(1).context().environment()).isEqualTo("UNKNOWN");
        assertThat(items.get(1).versionResolution()).isEqualTo(VersionResolution.UNRESOLVED);
        var manifest = parser.parseManifest(ScaParserTest.file("package.json", "{\"devDependencies\":{\"fixture-tool\":\"^1.0.0\"}}"));
        assertThat(manifest.get(0).context().paths().get(0).declarationFile()).isEqualTo("package.json");
        assertThat(manifest.get(0).context().environment()).isEqualTo("UNKNOWN");
        assertThat(manifest.get(0).versionResolution()).isEqualTo(VersionResolution.RANGE);
    }

    @Test void corruptDependencySectionDoesNotSilentlyParseAsAnEmptyGraph() {
        assertThatThrownBy(() -> parser.parseLock(ScaParserTest.file("package-lock.json",
                "{\"lockfileVersion\":3,\"packages\":{\"\":{\"dependencies\":[\"not-a-map\"]}}}")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
