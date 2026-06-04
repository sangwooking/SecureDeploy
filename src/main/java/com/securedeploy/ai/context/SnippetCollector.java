package com.securedeploy.ai.context;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import com.securedeploy.project.model.ProjectStructure;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class SnippetCollector {

    private static final int MAX_FILES = 10;
    private static final int MAX_CHARS_PER_FILE = 1_500;
    private static final int MAX_LINES_PER_FILE = 80;

    public SnippetGroup collect(ProjectStructure projectStructure) {
        List<SnippetCandidate> selected = projectStructure.analysisFiles().stream()
                .map(this::candidate)
                .filter(candidate -> candidate.type() != null)
                .sorted(Comparator.comparingInt(SnippetCandidate::priority).thenComparing(candidate -> candidate.file().relativePath()))
                .limit(MAX_FILES)
                .toList();

        List<AiCodeSnippet> securityConfigSnippets = new ArrayList<>();
        List<AiCodeSnippet> controllerSnippets = new ArrayList<>();
        List<AiCodeSnippet> serviceSnippets = new ArrayList<>();
        List<AiCodeSnippet> repositorySnippets = new ArrayList<>();
        List<AiCodeSnippet> configSnippets = new ArrayList<>();
        List<AiCodeSnippet> clientSnippets = new ArrayList<>();

        for (SnippetCandidate candidate : selected) {
            AiCodeSnippet snippet = new AiCodeSnippet(
                    candidate.file().relativePath(),
                    sanitize(truncate(candidate.file().lines()))
            );
            switch (candidate.type()) {
                case SECURITY_CONFIG -> securityConfigSnippets.add(snippet);
                case CONTROLLER -> controllerSnippets.add(snippet);
                case SERVICE -> serviceSnippets.add(snippet);
                case REPOSITORY -> repositorySnippets.add(snippet);
                case CONFIG -> configSnippets.add(snippet);
                case CLIENT -> clientSnippets.add(snippet);
            }
        }

        return new SnippetGroup(securityConfigSnippets, controllerSnippets, serviceSnippets, repositorySnippets, configSnippets, clientSnippets);
    }

    private SnippetCandidate candidate(ProjectFile file) {
        String path = file.relativePath();
        String name = path.substring(path.lastIndexOf('/') + 1);
        String lowerName = name.toLowerCase(Locale.ROOT);
        String lowerPath = path.toLowerCase(Locale.ROOT);

        if (file.type() == ProjectFileType.JAVA && name.contains("SecurityConfig")) {
            return new SnippetCandidate(file, SnippetType.SECURITY_CONFIG, 0);
        }
        if (isDevOpsConfig(file)) {
            return new SnippetCandidate(file, SnippetType.CONFIG, 1);
        }
        if (isClientEntry(file, lowerName, lowerPath)) {
            return new SnippetCandidate(file, SnippetType.CLIENT, 2);
        }
        if (file.type() == ProjectFileType.JAVA && name.endsWith("Controller.java")) {
            return new SnippetCandidate(file, SnippetType.CONTROLLER, 3);
        }
        if (isConfig(file, lowerName)) {
            return new SnippetCandidate(file, SnippetType.CONFIG, 4);
        }
        if (isClientSupport(file, lowerPath)) {
            return new SnippetCandidate(file, SnippetType.CLIENT, 5);
        }
        if (file.type() == ProjectFileType.JAVA && name.endsWith("Service.java")) {
            return new SnippetCandidate(file, SnippetType.SERVICE, 6);
        }
        if (file.type() == ProjectFileType.JAVA && name.endsWith("Repository.java")) {
            return new SnippetCandidate(file, SnippetType.REPOSITORY, 7);
        }
        return new SnippetCandidate(file, null, Integer.MAX_VALUE);
    }


    private boolean isDevOpsConfig(ProjectFile file) {
        return file.type() == ProjectFileType.DOCKERFILE
                || file.type() == ProjectFileType.DOCKER_COMPOSE
                || file.type() == ProjectFileType.GITHUB_ACTIONS
                || file.type() == ProjectFileType.NGINX_CONFIG
                || file.type() == ProjectFileType.KUBERNETES_CONFIG;
    }

    private boolean isConfig(ProjectFile file, String lowerName) {
        return (file.type() == ProjectFileType.YAML && ("application.yml".equals(lowerName) || "application.yaml".equals(lowerName)))
                || (file.type() == ProjectFileType.PROPERTIES && "application.properties".equals(lowerName))
                || file.type() == ProjectFileType.ENV
                || file.type() == ProjectFileType.ENV_FILE
                || file.type() == ProjectFileType.FRONTEND_CONFIG;
    }

    private boolean isClientEntry(ProjectFile file, String lowerName, String lowerPath) {
        return isFrontendSource(file)
                && ("app.jsx".equals(lowerName)
                || "app.tsx".equals(lowerName)
                || "main.jsx".equals(lowerName)
                || "main.tsx".equals(lowerName)
                || lowerPath.contains("/pages/")
                || lowerPath.contains("/components/"));
    }

    private boolean isClientSupport(ProjectFile file, String lowerPath) {
        return isFrontendSource(file)
                && (lowerPath.contains("/hooks/")
                || lowerPath.contains("/services/")
                || lowerPath.contains("/api/"));
    }

    private boolean isFrontendSource(ProjectFile file) {
        return file.type() == ProjectFileType.JAVASCRIPT
                || file.type() == ProjectFileType.TYPESCRIPT
                || file.type() == ProjectFileType.REACT;
    }

    private String truncate(List<String> lines) {
        StringBuilder builder = new StringBuilder();
        int limit = Math.min(lines.size(), MAX_LINES_PER_FILE);
        for (int i = 0; i < limit; i++) {
            String line = lines.get(i);
            if (builder.length() + line.length() + 1 > MAX_CHARS_PER_FILE) {
                builder.append("\n// ... snippet truncated for AI audit cost control");
                break;
            }
            builder.append(line).append('\n');
        }
        if (lines.size() > MAX_LINES_PER_FILE) {
            builder.append("// ... remaining lines omitted for AI audit cost control\n");
        }
        return builder.toString().trim();
    }

    private String sanitize(String content) {
        return content
                .replaceAll("(?i)(openai[_-]?api[_-]?key\s*[:=]\s*)([^\s\"']+)", "$1[REDACTED]")
                .replaceAll("(?i)((?:vite[_-]?)?[a-z0-9_]*api[_-]?key\s*[:=]\s*)([^\s\"']+)", "$1[REDACTED]")
                .replaceAll("(?i)(password\s*[:=]\s*)([^\s\"']+)", "$1[REDACTED]")
                .replaceAll("(?i)((?:vite[_-]?)?[a-z0-9_]*secret\s*[:=]\s*)([^\s\"']+)", "$1[REDACTED]")
                .replaceAll("(?i)((?:access|refresh)?token\s*[:=]\s*)([^\s\"']+)", "$1[REDACTED]")
                .replaceAll("(?i)(private[_-]?key\s*[:=]\s*)([^\s\"']+)", "$1[REDACTED]");
    }

    private record SnippetCandidate(ProjectFile file, SnippetType type, int priority) {
    }
}
