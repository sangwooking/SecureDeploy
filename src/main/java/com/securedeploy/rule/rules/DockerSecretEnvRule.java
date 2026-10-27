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
        var parsed=DockerEnvironment.inspect(file);
        if(parsed.complete()) {
            parsed.declarations().stream().filter(d->!d.kind().equals("EMPTY")).map(DockerEnvironment.Declaration::line).distinct().forEach(line->matches.add(new RuleMatch(
                    "DOCKER_SECRET_ENV",RuleCategory.CONTAINER_SECURITY,Severity.HIGH,file.relativePath(),line,
                    "Dockerfile ENV에 비밀정보 이름의 설정이 선언되어 있습니다. 리터럴·외부 참조를 구분해 실제 자격증명과 이미지 포함 여부를 확인하세요.",
                    "ENV와 ARG로 비밀값을 전달하지 말고 필요한 빌드 단계의 BuildKit secret mount 또는 런타임 비밀 저장소를 검토하세요. mount의 내용을 복사하거나 출력하면 다시 노출될 수 있습니다.",
                    "ENV credential setting; name and value omitted",com.securedeploy.rule.model.FalsePositiveRisk.MEDIUM,com.securedeploy.rule.model.DetectionConfidence.MEDIUM,
                    "DOCKER_ENV_DECLARATION_REVIEW: 비밀정보 이름의 ENV 선언 근거이며 실제 자격증명·최종 이미지 포함은 미검증입니다.")));
            return matches;
        }
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
