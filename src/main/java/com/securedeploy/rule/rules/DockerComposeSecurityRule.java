package com.securedeploy.rule.rules;

import com.securedeploy.analysis.deployment.ComposeInspector;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.*;
import java.util.*;
import org.springframework.stereotype.Component;

@Component
public class DockerComposeSecurityRule implements VulnerabilityRule {
    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isDockerCompose(file)) return List.of();
        return ComposeInspector.inspect(file).observations().stream()
                .filter(o -> Set.of("DOCKER_PRIVILEGED", "DOCKER_HOST_NETWORK").contains(o.ruleId()))
                .map(o -> new RuleMatch(o.ruleId(), RuleCategory.CONTAINER_SECURITY,
                        o.ruleId().equals("DOCKER_PRIVILEGED") ? Severity.HIGH : Severity.MEDIUM,
                        file.relativePath(), o.line(),
                        o.ruleId().equals("DOCKER_PRIVILEGED") ? "Compose 서비스에 privileged: true가 선언되어 컨테이너 격리가 약화될 수 있습니다."
                                : "Compose 서비스에 host 네트워크가 선언되어 호스트 네트워크와의 격리가 약화될 수 있습니다.",
                        "필요한 최소 권한과 격리된 네트워크를 사용하고 실제 활성 서비스·변수·override 파일을 확인하세요.",
                        o.scope() + " " + o.setting() + "=" + o.valueSummary(), FalsePositiveRisk.LOW, DetectionConfidence.HIGH,
                        "서비스의 정적 선언을 확인했습니다. 실제 배포 적용·환경변수·override·공격 가능성은 미검증입니다."))
                .toList();
    }
}
