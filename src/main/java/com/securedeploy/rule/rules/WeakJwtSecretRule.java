package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class WeakJwtSecretRule implements VulnerabilityRule {

    private static final Set<String> WEAK_VALUES = Set.of(
            "secret",
            "jwtsecret",
            "changeme",
            "password",
            "123456",
            "test",
            "dev"
    );

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        return ConfigFileParser.parse(file).stream()
                .filter(entry -> "jwt.secret".equals(entry.normalizedKey()))
                .filter(entry -> !ConfigFileParser.isPlaceholder(entry.value()))
                .filter(entry -> isWeak(entry.value()))
                .map(entry -> new RuleMatch(
                        "WEAK_JWT_SECRET",
                        RuleCategory.AUTHENTICATION,
                        Severity.HIGH,
                        file.relativePath(),
                        entry.line(),
                        "JWT secret 값이 짧거나 추측하기 쉬운 값입니다.",
                        "JWT secret은 충분히 긴 랜덤 값으로 생성하고 환경변수 또는 Secret Manager로 관리해야 합니다.",
                        "jwt.secret=<redacted>, length=" + entry.value().length()
                ))
                .toList();
    }

    private boolean isWeak(String value) {
        String normalized = value.toLowerCase(Locale.ROOT).strip();
        return normalized.length() < 32
                || WEAK_VALUES.contains(normalized)
                || normalized.matches("(.)\\1{5,}")
                || normalized.matches("[0-9]+")
                || normalized.matches("[a-z]+")
                || normalized.matches("[A-Z]+");
    }
}
