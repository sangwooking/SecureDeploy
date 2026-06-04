package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class StacktraceExposureRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        return ConfigFileParser.parse(file).stream()
                .filter(entry -> "server.error.include.stacktrace".equals(entry.normalizedKey()))
                .filter(entry -> "always".equalsIgnoreCase(entry.value()))
                .map(entry -> new RuleMatch(
                        "STACKTRACE_EXPOSURE",
                        RuleCategory.CONFIGURATION,
                        Severity.MEDIUM,
                        file.relativePath(),
                        entry.line(),
                        "오류 응답에 stacktrace가 항상 포함되도록 설정되어 있습니다.",
                        "운영 환경에서는 stacktrace 노출을 비활성화하거나 on_param 등 제한적인 설정을 사용해야 합니다.",
                        entry.evidence()
                ))
                .toList();
    }
}
