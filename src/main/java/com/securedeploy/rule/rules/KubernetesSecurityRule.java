package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class KubernetesSecurityRule implements VulnerabilityRule {

    private static final Pattern LATEST_IMAGE = Pattern.compile("(?i)^\s*image\s*:\s*[^\s:]+:latest\b");
    private static final Pattern SECRET_KEY = Pattern.compile("(?i)^\s*(password|token|secret|api[_-]?key|private[_-]?key)\s*:");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isKubernetes(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        boolean inSecret = false;
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.matches(".*kind\s*:\s*secret.*")) {
                inSecret = true;
            }
            if (lower.matches(".*privileged\s*:\s*true.*")) {
                matches.add(match(file, index + 1, "K8S_PRIVILEGED_CONTAINER", Severity.HIGH, "Kubernetes 컨테이너에 privileged: true가 설정되어 있습니다.", "privileged 설정을 제거하고 Pod Security Standards, SecurityContext 최소 권한 설정을 적용하세요.", line));
            }
            if (LATEST_IMAGE.matcher(line).find()) {
                matches.add(match(file, index + 1, "K8S_LATEST_IMAGE", Severity.MEDIUM, "Kubernetes manifest에서 latest 이미지 태그가 사용되었습니다.", "배포 재현성을 위해 고정 이미지 태그 또는 digest를 사용하세요.", line));
            }
            if (lower.matches(".*type\s*:\s*nodeport.*")) {
                matches.add(match(file, index + 1, "K8S_NODEPORT_EXPOSURE", Severity.MEDIUM, "Kubernetes Service가 NodePort로 외부 노출될 수 있습니다. 노출 범위 검토가 필요합니다.", "Ingress, LoadBalancer, NetworkPolicy와 방화벽 정책을 함께 검토하고 필요한 포트만 노출하세요.", line));
            }
            if (inSecret && SECRET_KEY.matcher(line).find()) {
                matches.add(match(file, index + 1, "K8S_SECRET_PLAIN_TEXT", Severity.HIGH, "Kubernetes Secret manifest에 평문 비밀 값으로 보이는 항목이 포함되어 있습니다.", "Secret 파일을 저장소에 커밋하지 말고 SealedSecret, External Secrets, Secret Manager 연동을 사용하세요.", DevOpsEvidenceSanitizer.maskSecrets(line.strip())));
            }
        }
        return matches;
    }

    private RuleMatch match(ProjectFile file, int line, String ruleId, Severity severity, String message, String recommendation, String evidence) {
        return new RuleMatch(ruleId, RuleCategory.KUBERNETES_SECURITY, severity, file.relativePath(), line, message, recommendation, evidence.strip());
    }
}
