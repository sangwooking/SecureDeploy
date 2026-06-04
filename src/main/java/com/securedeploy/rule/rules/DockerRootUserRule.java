package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class DockerRootUserRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isDockerfile(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        boolean hasUser = false;
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String trimmed = lines.get(index).strip();
            String lower = trimmed.toLowerCase(Locale.ROOT);
            if (lower.startsWith("user ")) {
                hasUser = true;
                String user = lower.substring(5).strip();
                if ("root".equals(user) || "0".equals(user)) {
                    matches.add(match(file, index + 1, trimmed, "Dockerfile에서 USER root가 설정되어 컨테이너가 root 권한으로 실행될 수 있습니다."));
                }
            }
        }

        if (!hasUser) {
            matches.add(match(file, 1, "USER directive missing", "Dockerfile에 USER 지시어가 없습니다. 기본 root 사용자로 실행될 수 있습니다."));
        }
        return matches;
    }

    private RuleMatch match(ProjectFile file, int line, String evidence, String message) {
        return new RuleMatch(
                "DOCKER_ROOT_USER",
                RuleCategory.CONTAINER_SECURITY,
                Severity.HIGH,
                file.relativePath(),
                line,
                message,
                "컨테이너 내부 전용 non-root 사용자를 생성하고 USER appuser처럼 명시적으로 전환하세요.",
                evidence
        );
    }
}
