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
public class DockerSecretEnvRule implements VulnerabilityRule {

    private static final Pattern SECRET_ENV = Pattern.compile("(?i)^\s*ENV\s+[^#]*(PASSWORD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)[^=]*=");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isDockerfile(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (SECRET_ENV.matcher(line).find()) {
                matches.add(new RuleMatch(
                        "DOCKER_SECRET_ENV",
                        RuleCategory.CONTAINER_SECURITY,
                        Severity.HIGH,
                        file.relativePath(),
                        index + 1,
                        "Dockerfile ENV에 비밀 값으로 보이는 설정이 하드코딩되어 있습니다.",
                        "이미지 레이어에 secret이 남을 수 있으므로 런타임 환경변수, Docker secrets, Kubernetes Secret 또는 Secret Manager를 사용하세요.",
                        DevOpsEvidenceSanitizer.maskSecrets(line.strip())
                ));
            }
        }
        return matches;
    }
}
