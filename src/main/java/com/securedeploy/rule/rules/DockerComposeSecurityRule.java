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
public class DockerComposeSecurityRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isDockerCompose(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.matches(".*privileged\s*:\s*true.*")) {
                matches.add(new RuleMatch(
                        "DOCKER_PRIVILEGED",
                        RuleCategory.CONTAINER_SECURITY,
                        Severity.HIGH,
                        file.relativePath(),
                        index + 1,
                        "docker-compose에서 privileged: true가 설정되어 있습니다. 컨테이너 격리가 약화될 수 있습니다.",
                        "특권 모드를 제거하고 필요한 Linux capability만 최소 권한으로 부여하세요.",
                        line.strip()
                ));
            }
            if (lower.matches(".*network_mode\s*:\s*host.*")) {
                matches.add(new RuleMatch(
                        "DOCKER_HOST_NETWORK",
                        RuleCategory.CONTAINER_SECURITY,
                        Severity.MEDIUM,
                        file.relativePath(),
                        index + 1,
                        "docker-compose에서 host 네트워크 모드가 사용되었습니다. 호스트 네트워크와 격리가 약화될 수 있습니다.",
                        "bridge 네트워크와 명시적 포트 매핑을 사용하고, host network가 꼭 필요한지 검토하세요.",
                        line.strip()
                ));
            }
        }
        return matches;
    }
}
