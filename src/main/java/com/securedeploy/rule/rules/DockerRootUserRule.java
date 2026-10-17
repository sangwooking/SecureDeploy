package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class DockerRootUserRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isDockerfile(file)) {
            return List.of();
        }

        var runtime = DockerRuntimeUser.inspect(file);
        if (runtime.status() != DockerRuntimeUser.Status.ROOT_DECLARED) return List.of();
        return List.of(new RuleMatch("DOCKER_ROOT_USER", RuleCategory.CONTAINER_SECURITY, Severity.HIGH,
                file.relativePath(), runtime.line(),
                "Dockerfile의 기본 최종 stage가 root 사용자 설정을 유지하거나 상속합니다.",
                "최종 실행 stage에서 non-root USER를 지정하고 실제 build target과 배포 user override를 확인하세요.",
                "Default final stage: root USER declaration or inheritance",
                com.securedeploy.rule.model.FalsePositiveRisk.LOW, com.securedeploy.rule.model.DetectionConfidence.HIGH,
                "기본 최종 stage의 FROM/USER 순서를 확인했습니다. 기반 이미지 내부, 별도 build target, 실행 시 사용자 변경은 검증하지 않았습니다."));
    }

}
