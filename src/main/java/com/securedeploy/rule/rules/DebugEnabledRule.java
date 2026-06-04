package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class DebugEnabledRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        return ConfigFileParser.parse(file).stream()
                .filter(entry -> "debug".equals(entry.normalizedKey()))
                .filter(entry -> ConfigFileParser.isBooleanTrue(entry.value()))
                .map(entry -> new RuleMatch(
                        "DEBUG_ENABLED",
                        RuleCategory.CONFIGURATION,
                        Severity.MEDIUM,
                        file.relativePath(),
                        entry.line(),
                        "debug 모드가 활성화되어 있습니다.",
                        "운영 환경에서는 debug=false로 설정하거나 debug 설정을 제거해야 합니다.",
                        entry.evidence()
                ))
                .toList();
    }
}
