package com.securedeploy.rule.rules;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class DockerRuntimeUserTest {
    private List<com.securedeploy.rule.model.RuleMatch> scan(String input) {
        return new DockerRootUserRule().evaluate(new ProjectFile(Path.of("Dockerfile"), "Dockerfile",
                ProjectFileType.DOCKERFILE, input.lines().toList()));
    }
    @Test void temporaryBuildRootDoesNotBecomeRuntimeRoot() {
        assertThat(scan("FROM example:1 AS base\nUSER 10001\nFROM base AS worker\nUSER root\nRUN echo fixture\nUSER 10001\nCMD [\"worker\"]")).isEmpty();
        assertThat(scan("FROM example:1 AS builder\nUSER root\nFROM other:1\nUSER app")).isEmpty();
    }
    @Test void finalRootAndInheritedRootRemainFindings() {
        for (String user : List.of("root", "0", "0:1000", "root:app", "000")) {
            assertThat(scan("FROM example:1 AS base\nUSER " + user + "\nFROM base AS final")).hasSize(1);
        }
        assertThat(scan("FROM example:1\nUSER app\nUSER root")).hasSize(1);
    }
    @Test void unknownImageAndDynamicUserAreNotAssertedAsRoot() {
        assertThat(scan("FROM example:1\nCMD [\"service\"]")).isEmpty();
        assertThat(scan("FROM example:1\nUSER ${RUNTIME_USER}")).isEmpty();
        assertThat(scan("FROM example:1 AS base\nUSER app\nFROM other:1")).isEmpty();
    }
    @Test void instructionsInsideRunHeredocAreNotDockerInstructions() {
        assertThat(scan("FROM example:1\nUSER app\nRUN <<EOF\nUSER root\nEOF\nCMD [\"worker\"]")).isEmpty();
    }
}
