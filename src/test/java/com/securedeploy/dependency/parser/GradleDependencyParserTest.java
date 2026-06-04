package com.securedeploy.dependency.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class GradleDependencyParserTest {

    private final GradleDependencyParser parser = new GradleDependencyParser();

    @Test
    void parsesSingleQuoteDoubleQuoteAndMapNotation() {
        ProjectFile file = new ProjectFile(
                Path.of("build.gradle"),
                "gradle-service/build.gradle",
                ProjectFileType.GRADLE_BUILD,
                List.of(
                        "dependencies {",
                        "    implementation 'org.springframework:spring-webmvc:5.3.10'",
                        "    api \"commons-collections:commons-collections:3.2.1\"",
                        "    testImplementation group: 'com.fasterxml.jackson.core', name: 'jackson-databind', version: '2.9.10'",
                        "}"
                )
        );

        List<DependencyInfo> dependencies = parser.parse(file);

        assertThat(dependencies)
                .extracting(DependencyInfo::name)
                .containsExactly(
                        "org.springframework:spring-webmvc",
                        "commons-collections:commons-collections",
                        "com.fasterxml.jackson.core:jackson-databind"
                );
        assertThat(dependencies)
                .extracting(DependencyInfo::version)
                .containsExactly("5.3.10", "3.2.1", "2.9.10");
    }
}
