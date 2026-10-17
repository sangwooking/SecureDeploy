package com.securedeploy.sca;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertTimeout;

/** Independently composed declaration variants, not private project source or an accuracy benchmark. */
class PythonScaVariationTest {
    @ParameterizedTest @CsvSource({
        "fixtures/requirements-prod.in,Alpha..Lib==2.4.0,EXACT",
        "tools/requirements/build.txt,ALPHA_lib[fast-io]==2.4.0,EXACT",
        "requirements_QA.txt,alpha-lib (==2.4.0),EXACT",
        "services/requirements.txt,alpha-lib == 2.4.0 ; os_name not in 'nt',EXACT",
        "requirements.txt,alpha-lib!=2.4.0,RANGE",
        "requirements.txt,alpha-lib==2.*,RANGE",
        "requirements.txt,alpha-lib~=2.4,RANGE",
        "requirements.txt,alpha-lib @ file:///synthetic/local,UNRESOLVED",
        "requirements.txt,alpha-lib==v2.4,UNRESOLVED",
        "requirements.txt,alpha-lib==2.4+vendor,UNRESOLVED",
        "requirements.txt,alpha-lib==2.4 ; unknown == 'x',UNRESOLVED",
        "requirements.txt,alpha-lib => 2.4,UNRESOLVED"
    }) void declarationMatrix(String file, String declaration, VersionResolution expected) {
        var parsed = PythonScaParserTest.parse(file, declaration);
        assertThat(parsed.components()).hasSize(1);
        assertThat(parsed.components().get(0).versionResolution()).isEqualTo(expected);
        assertThat(parsed.components().get(0).packageName()).isEqualTo("alpha-lib");
    }
    @Test void equivalentLayoutsAndOrderingPreserveNormalizedIdentity() {
        var a = PythonScaParserTest.parse("requirements.txt", "--requirement=requirements/base.txt\n--constraint=constraints.txt",
                "requirements/base.txt", "Alpha.Lib\n", "constraints.txt", "alpha-lib==2.4");
        var b = PythonScaParserTest.parse("backend/constraints-prod.txt", "ALPHA_LIB==2.4",
                "backend/requirements-prod.txt", "-cconstraints-prod.txt\n-rrequirements/common.txt",
                "backend/requirements/common.txt", "alpha-lib");
        assertThat(a.components()).hasSize(1); assertThat(b.components()).hasSize(1);
        assertThat(a.components().get(0).identity()).isEqualTo(b.components().get(0).identity());
        assertThat(a.components().get(0).python().versionOrigin()).isEqualTo("CONSTRAINT_PIN");
    }
    @Test void customIndexSpellingsAndToolOverridesCannotBecomeRegistryProof() {
        for (var option : List.of("-ihttps://example.invalid/simple", "-f./wheels", "--extra-index-url=https://example.invalid")) {
            assertThat(PythonScaParserTest.parse("requirements.txt", option + "\nfixture==1.0").components())
                    .allMatch(c -> c.versionResolution() == VersionResolution.UNRESOLVED);
        }
        assertThat(PythonScaParserTest.parse("pylock.production.toml", "lock-version='1.0'").observations().get(0).status()).isEqualTo("UNSUPPORTED");
    }
    @Test void deepIncludesLargeInventoriesAndMixedEcosystemsStayBounded() {
        assertTimeout(Duration.ofSeconds(5), () -> {
            List<ProjectFile> chain = new ArrayList<>();
            for (int i = 0; i < 12; i++) chain.add(ScaParserTest.file("requirements-" + i + ".txt",
                    "-r requirements-" + (i + 1) + ".txt\nfixture-" + i + "==1.0"));
            var limited = new PythonManifestParser().collect(chain);
            assertThat(limited.observations()).anyMatch(o -> o.status().equals("LIMIT_EXCEEDED"));
            List<ProjectFile> many = new ArrayList<>();
            for (int i = 0; i < 101; i++) many.add(ScaParserTest.file("requirements-" + i + ".txt", "fixture==1.0"));
            assertThat(new PythonManifestParser().collect(many).observations()).anyMatch(o -> o.status().equals("LIMIT_EXCEEDED"));
            String repeated = "fixture==1.0\n".repeat(5000);
            var mixed = new com.securedeploy.project.model.ProjectStructure(java.nio.file.Path.of("."), List.of(
                    ScaParserTest.file("requirements.txt", repeated), ScaParserTest.file("package.json", "{\"dependencies\":{\"fixture\":\"1.0.0\"}}")));
            var inventory = new ScaManifestCollector(new com.fasterxml.jackson.databind.ObjectMapper()).collect(mixed);
            assertThat(inventory.components()).hasSizeLessThanOrEqualTo(5000);
            assertThat(inventory.warnings()).isNotEmpty();
        });
    }
}
