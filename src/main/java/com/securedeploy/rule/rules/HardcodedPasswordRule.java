package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class HardcodedPasswordRule implements VulnerabilityRule {

    private static final Set<String> PASSWORD_KEYS = Set.of(
            "password",
            "db.password",
            "database.password",
            "datasource.password",
            "spring.datasource.password"
    );

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        return ConfigFileParser.parse(file).stream()
                .filter(entry -> isPasswordKey(entry.normalizedKey()))
                .filter(entry -> !ConfigFileParser.isPlaceholder(entry.value()))
                .filter(entry -> !isMasked(entry.value()))
                .map(entry -> new RuleMatch(
                        "HARDCODED_PASSWORD",
                        RuleCategory.SECRET_MANAGEMENT,
                        Severity.HIGH,
                        file.relativePath(),
                        entry.line(),
                        "하드코딩된 비밀번호가 발견되었습니다.",
                        "비밀번호는 환경변수 또는 Secret Manager로 분리해야 합니다.",
                        entry.evidence()
                ))
                .toList();
    }

    private boolean isPasswordKey(String normalizedKey) {
        return PASSWORD_KEYS.contains(normalizedKey) || normalizedKey.endsWith(".password");
    }

    private boolean isMasked(String value) {
        return value.matches("[*xX]{4,}");
    }
}
