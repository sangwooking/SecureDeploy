package com.securedeploy.dependency.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class PomXmlDependencyParserTest {

    private final PomXmlDependencyParser parser = new PomXmlDependencyParser();

    @Test
    void parsesMavenDependenciesWithExplicitVersions() {
        ProjectFile file = new ProjectFile(
                Path.of("pom.xml"),
                "backend/pom.xml",
                ProjectFileType.XML,
                List.of(
                        "<project>",
                        "  <dependencies>",
                        "    <dependency>",
                        "      <groupId>org.apache.logging.log4j</groupId>",
                        "      <artifactId>log4j-core</artifactId>",
                        "      <version>2.14.1</version>",
                        "    </dependency>",
                        "    <dependency>",
                        "      <groupId>com.fasterxml.jackson.core</groupId>",
                        "      <artifactId>jackson-databind</artifactId>",
                        "      <version>2.9.10</version>",
                        "    </dependency>",
                        "  </dependencies>",
                        "</project>"
                )
        );

        List<DependencyInfo> dependencies = parser.parse(file);

        assertThat(dependencies)
                .extracting(DependencyInfo::name)
                .containsExactly("org.apache.logging.log4j:log4j-core", "com.fasterxml.jackson.core:jackson-databind");
        assertThat(dependencies)
                .extracting(DependencyInfo::version)
                .containsExactly("2.14.1", "2.9.10");
    }
}
