package com.securedeploy.project.service;

import com.securedeploy.project.model.ProjectFileType;
import java.nio.file.Path;
import java.util.Optional;
import org.springframework.stereotype.Component;

@Component
public class ProjectFileCollector {

    public Optional<ProjectFileType> resolveAnalysisFileType(Path path) {
        String fileName = path.getFileName().toString();
        String lowerName = fileName.toLowerCase();
        String normalizedPath = path.toString().replace('\\', '/').toLowerCase();

        if ("dockerfile".equals(lowerName)) {
            return Optional.of(ProjectFileType.DOCKERFILE);
        }
        if ("docker-compose.yml".equals(lowerName) || "docker-compose.yaml".equals(lowerName)) {
            return Optional.of(ProjectFileType.DOCKER_COMPOSE);
        }
        if (isGitHubActionsWorkflow(normalizedPath, lowerName)) {
            return Optional.of(ProjectFileType.GITHUB_ACTIONS);
        }
        if (isNginxConfig(lowerName)) {
            return Optional.of(ProjectFileType.NGINX_CONFIG);
        }
        if (isKubernetesConfig(normalizedPath, lowerName)) {
            return Optional.of(ProjectFileType.KUBERNETES_CONFIG);
        }
        if (lowerName.endsWith(".java")) {
            return Optional.of(ProjectFileType.JAVA);
        }
        if ("application.yml".equals(lowerName) || "application.yaml".equals(lowerName)) {
            return Optional.of(ProjectFileType.YAML);
        }
        if ("application.properties".equals(lowerName)) {
            return Optional.of(ProjectFileType.PROPERTIES);
        }
        if (isEnvFile(lowerName)) {
            return Optional.of(".env".equals(lowerName) ? ProjectFileType.ENV : ProjectFileType.ENV_FILE);
        }
        if ("pom.xml".equals(lowerName)) {
            return Optional.of(ProjectFileType.XML);
        }
        if ("package.json".equals(lowerName)) {
            return Optional.of(ProjectFileType.PACKAGE_JSON);
        }
        if ("package-lock.json".equals(lowerName) || "yarn.lock".equals(lowerName) || "pnpm-lock.yaml".equals(lowerName)) {
            return Optional.of(ProjectFileType.LOCK_FILE);
        }
        if (isFrontendConfig(lowerName)) {
            return Optional.of(ProjectFileType.FRONTEND_CONFIG);
        }
        if (lowerName.endsWith(".jsx") || lowerName.endsWith(".tsx")) {
            return Optional.of(ProjectFileType.REACT);
        }
        if (lowerName.endsWith(".ts")) {
            return Optional.of(ProjectFileType.TYPESCRIPT);
        }
        if (lowerName.endsWith(".js")) {
            return Optional.of(ProjectFileType.JAVASCRIPT);
        }

        return Optional.empty();
    }

    private boolean isEnvFile(String lowerName) {
        return ".env".equals(lowerName)
                || ".env.local".equals(lowerName)
                || ".env.development".equals(lowerName)
                || ".env.production".equals(lowerName);
    }

    private boolean isFrontendConfig(String lowerName) {
        return "vite.config.js".equals(lowerName)
                || "vite.config.ts".equals(lowerName)
                || "next.config.js".equals(lowerName)
                || "next.config.ts".equals(lowerName);
    }

    private boolean isGitHubActionsWorkflow(String normalizedPath, String lowerName) {
        return normalizedPath.contains("/.github/workflows/")
                && (lowerName.endsWith(".yml") || lowerName.endsWith(".yaml"));
    }

    private boolean isNginxConfig(String lowerName) {
        return "nginx.conf".equals(lowerName)
                || "default.conf".equals(lowerName)
                || lowerName.endsWith(".nginx.conf");
    }

    private boolean isKubernetesConfig(String normalizedPath, String lowerName) {
        if (!(lowerName.endsWith(".yml") || lowerName.endsWith(".yaml"))) {
            return false;
        }
        return normalizedPath.contains("/k8s/")
                || "deployment.yml".equals(lowerName)
                || "deployment.yaml".equals(lowerName)
                || "service.yml".equals(lowerName)
                || "service.yaml".equals(lowerName)
                || "ingress.yml".equals(lowerName)
                || "ingress.yaml".equals(lowerName);
    }
}
