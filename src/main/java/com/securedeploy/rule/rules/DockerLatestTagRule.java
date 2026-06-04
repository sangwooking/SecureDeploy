package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class DockerLatestTagRule implements VulnerabilityRule {

    private static final Pattern LATEST_FROM = Pattern.compile("(?i)^\s*FROM\s+[^\s:]+:latest\b");
    private static final Pattern LATEST_IMAGE = Pattern.compile("(?i)^\s*image\s*:\s*[^\s:]+:latest\b");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isDockerfile(file) && !RuleFileTypes.isDockerCompose(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (LATEST_FROM.matcher(line).find() || LATEST_IMAGE.matcher(line).find()) {
                matches.add(new RuleMatch(
                        "DOCKER_LATEST_TAG",
                        RuleCategory.CONTAINER_SECURITY,
                        Severity.MEDIUM,
                        file.relativePath(),
                        index + 1,
                        "Docker 이미지에 latest 태그가 사용되었습니다. 빌드 재현성과 배포 안정성이 떨어질 수 있습니다.",
                        "운영 배포에는 node:20.11.1, nginx:1.25.4처럼 고정 버전 또는 digest pinning을 사용하세요.",
                        line.strip()
                ));
            }
        }
        return matches;
    }
}
