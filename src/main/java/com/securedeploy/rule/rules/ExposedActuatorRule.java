package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class ExposedActuatorRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        return ConfigFileParser.parse(file).stream()
                .filter(entry -> "management.endpoints.web.exposure.include".equals(entry.normalizedKey()))
                .filter(entry -> "*".equals(entry.value()))
                .map(entry -> new RuleMatch(
                        "EXPOSED_ACTUATOR",
                        RuleCategory.CONFIGURATION,
                        Severity.HIGH,
                        file.relativePath(),
                        entry.line(),
                        "Actuator 엔드포인트가 전체 노출되도록 설정되어 있습니다.",
                        "운영 환경에서는 health, info 등 필요한 엔드포인트만 명시적으로 노출해야 합니다.",
                        entry.evidence()
                ))
                .toList();
    }
}
