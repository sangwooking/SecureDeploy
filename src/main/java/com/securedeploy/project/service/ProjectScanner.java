package com.securedeploy.project.service;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectStructure;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class ProjectScanner {

    private final ProjectFileCollector fileCollector;

    public ProjectScanner(ProjectFileCollector fileCollector) {
        this.fileCollector = fileCollector;
    }

    public ProjectStructure scan(Path projectRoot) {
        try (var paths = Files.walk(projectRoot)) {
            List<ProjectFile> files = paths
                    .filter(Files::isRegularFile)
                    .flatMap(path -> fileCollector.resolveAnalysisFileType(path)
                            .map(type -> new ProjectFile(
                                    path,
                                    normalizeRelativePath(projectRoot, path),
                                    type,
                                    readLines(path)
                            ))
                            .stream())
                    .toList();

            return new ProjectStructure(projectRoot, files);
        } catch (IOException exception) {
            throw new SecureDeployException(HttpStatus.INTERNAL_SERVER_ERROR, "프로젝트 파일 탐색 중 오류가 발생했습니다.");
        }
    }

    private String normalizeRelativePath(Path projectRoot, Path path) {
        return projectRoot.relativize(path).toString().replace('\\', '/');
    }

    private List<String> readLines(Path path) {
        try {
            return Files.readAllLines(path, StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new SecureDeployException(HttpStatus.INTERNAL_SERVER_ERROR, "분석 대상 파일을 읽을 수 없습니다.");
        }
    }
}
