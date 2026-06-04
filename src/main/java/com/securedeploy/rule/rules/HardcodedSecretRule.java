package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class HardcodedSecretRule implements VulnerabilityRule {

    private static final Set<String> SECRET_KEYS = Set.of(
            "secret",
            "jwt.secret",
            "api.key",
            "apikey",
            "client.secret",
            "oauth.client.secret"
    );

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        return ConfigFileParser.parse(file).stream()
                .filter(entry -> isSecretKey(entry.normalizedKey()))
                .filter(entry -> !ConfigFileParser.isPlaceholder(entry.value()))
                .map(entry -> new RuleMatch(
                        "HARDCODED_SECRET",
                        RuleCategory.SECRET_MANAGEMENT,
                        Severity.HIGH,
                        file.relativePath(),
                        entry.line(),
                        "하드코딩된 시크릿 값이 발견되었습니다.",
                        "시크릿 값은 환경변수 또는 Secret Manager로 분리해야 합니다.",
                        entry.evidence()
                ))
                .toList();
    }

    private boolean isSecretKey(String normalizedKey) {
        return SECRET_KEYS.contains(normalizedKey)
                || normalizedKey.endsWith(".secret")
                || normalizedKey.endsWith(".api.key");
    }
}
