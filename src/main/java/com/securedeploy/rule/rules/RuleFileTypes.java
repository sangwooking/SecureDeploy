package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;

final class RuleFileTypes {

    private RuleFileTypes() {
    }

    static boolean isJava(ProjectFile file) {
        return file.type() == ProjectFileType.JAVA;
    }

    static boolean isConfiguration(ProjectFile file) {
        return file.type() == ProjectFileType.YAML
                || file.type() == ProjectFileType.PROPERTIES
                || file.type() == ProjectFileType.ENV
                || file.type() == ProjectFileType.ENV_FILE;
    }

    static boolean isPom(ProjectFile file) {
        return file.type() == ProjectFileType.XML && file.relativePath().endsWith("pom.xml");
    }

    static boolean isGradleBuild(ProjectFile file) {
        return file.type() == ProjectFileType.GRADLE_BUILD;
    }

    static boolean isLockFile(ProjectFile file) {
        return file.type() == ProjectFileType.LOCK_FILE;
    }

    static boolean isFrontendSource(ProjectFile file) {
        return file.type() == ProjectFileType.JAVASCRIPT
                || file.type() == ProjectFileType.TYPESCRIPT
                || file.type() == ProjectFileType.REACT;
    }

    static boolean isFrontendSecretCandidate(ProjectFile file) {
        return isFrontendSource(file)
                || file.type() == ProjectFileType.ENV
                || file.type() == ProjectFileType.ENV_FILE
                || file.type() == ProjectFileType.FRONTEND_CONFIG;
    }

    static boolean isPackageJson(ProjectFile file) {
        return file.type() == ProjectFileType.PACKAGE_JSON;
    }

    static boolean isDockerfile(ProjectFile file) {
        return file.type() == ProjectFileType.DOCKERFILE;
    }

    static boolean isDockerCompose(ProjectFile file) {
        return file.type() == ProjectFileType.DOCKER_COMPOSE;
    }

    static boolean isGitHubActions(ProjectFile file) {
        return file.type() == ProjectFileType.GITHUB_ACTIONS;
    }

    static boolean isKubernetes(ProjectFile file) {
        return file.type() == ProjectFileType.KUBERNETES_CONFIG;
    }

    static boolean isNginx(ProjectFile file) {
        return file.type() == ProjectFileType.NGINX_CONFIG;
    }
}
