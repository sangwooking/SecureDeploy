package com.securedeploy.dependency.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class PackageJsonDependencyParserTest {

    private final PackageJsonDependencyParser parser = new PackageJsonDependencyParser();

    @Test
    void parsesDependenciesAndDevDependencies() {
        ProjectFile file = new ProjectFile(
                Path.of("package.json"),
                "frontend/package.json",
                ProjectFileType.PACKAGE_JSON,
                List.of(
                        "{",
                        "  \"dependencies\": {",
                        "    \"lodash\": \"4.17.10\",",
                        "    \"axios\": \"^0.20.0\"",
                        "  },",
                        "  \"devDependencies\": {",
                        "    \"minimist\": \"~1.2.0\"",
                        "  }",
                        "}"
                )
        );

        List<DependencyInfo> dependencies = parser.parse(file);

        assertThat(dependencies)
                .extracting(DependencyInfo::name)
                .containsExactly("lodash", "axios", "minimist");
        assertThat(dependencies)
                .extracting(DependencyInfo::version)
                .containsExactly("4.17.10", "0.20.0", "1.2.0");
    }
}
