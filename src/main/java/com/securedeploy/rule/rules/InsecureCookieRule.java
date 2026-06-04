package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class InsecureCookieRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        return ConfigFileParser.parse(file).stream()
                .filter(entry -> isCookieSecurityKey(entry.normalizedKey()))
                .filter(entry -> ConfigFileParser.isBooleanFalse(entry.value()))
                .map(entry -> new RuleMatch(
                        "INSECURE_COOKIE",
                        RuleCategory.CONFIGURATION,
                        Severity.MEDIUM,
                        file.relativePath(),
                        entry.line(),
                        "쿠키 보안 속성이 비활성화되어 있습니다.",
                        "운영 환경에서는 secure 및 http-only 속성을 활성화해 쿠키 탈취 위험을 낮춰야 합니다.",
                        entry.evidence()
                ))
                .toList();
    }

    private boolean isCookieSecurityKey(String normalizedKey) {
        return "secure".equals(normalizedKey)
                || "http.only".equals(normalizedKey)
                || "http.cookie.secure".equals(normalizedKey)
                || "http.cookie.http.only".equals(normalizedKey)
                || normalizedKey.endsWith(".secure")
                || normalizedKey.endsWith(".http.only");
    }
}
