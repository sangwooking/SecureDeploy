package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class LocalStorageTokenRule implements VulnerabilityRule {

    private static final Pattern TOKEN_KEY = Pattern.compile("(?i)(token|jwt|accessToken|refreshToken)");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isFrontendSource(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (isTokenStorage(line)) {
                matches.add(new RuleMatch(
                        "LOCAL_STORAGE_TOKEN",
                        RuleCategory.CLIENT_STORAGE,
                        Severity.HIGH,
                        file.relativePath(),
                        index + 1,
                        "localStorage에 인증 토큰을 저장하거나 조회하고 있습니다. XSS 취약점이 존재할 경우 토큰 탈취 위험이 있습니다.",
                        "가능하면 HttpOnly Secure Cookie 기반 인증 방식을 고려하고, 불가피하게 Web Storage를 쓴다면 토큰 수명 단축과 XSS 방어를 강화해야 합니다.",
                        FrontendEvidenceSanitizer.maskSecrets(line.strip())
                ));
            }
        }
        return matches;
    }

    private boolean isTokenStorage(String line) {
        return line.contains("localStorage")
                && (line.contains("setItem") || line.contains("getItem"))
                && TOKEN_KEY.matcher(line).find();
    }
}

