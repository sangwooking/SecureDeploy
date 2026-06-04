package com.securedeploy.dependency.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class DockerImageDependencyParserTest {

    private final DockerImageDependencyParser parser = new DockerImageDependencyParser();

    @Test
    void parsesDockerfileFromImages() {
        ProjectFile file = new ProjectFile(
                Path.of("Dockerfile"),
                "docker/Dockerfile",
                ProjectFileType.DOCKERFILE,
                List.of(
                        "FROM ubuntu:18.04 AS base",
                        "RUN apt-get update",
                        "FROM node:latest AS web"
                )
        );

        List<DependencyInfo> dependencies = parser.parse(file);

        assertThat(dependencies)
                .extracting(DependencyInfo::name)
                .containsExactly("ubuntu", "node");
        assertThat(dependencies)
                .extracting(DependencyInfo::version)
                .containsExactly("18.04", "latest");
    }
}
