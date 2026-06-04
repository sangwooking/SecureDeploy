package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class HardcodedFrontendSecretRule implements VulnerabilityRule {

    private static final Pattern ENV_SECRET = Pattern.compile("(?i)\b((?:VITE_)?[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN)[A-Z0-9_]*)\s*=\s*([^\s#]+)");
    private static final Pattern JS_SECRET = Pattern.compile("(?i)(api[_-]?key|secret|token|accessToken|refreshToken)[\"']?\s*[:=]\s*[\"']([^\"']{8,})[\"']");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isFrontendSecretCandidate(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            addEnvMatch(file, matches, line, index + 1);
            addJsMatch(file, matches, line, index + 1);
        }
        return matches;
    }

    private void addEnvMatch(ProjectFile file, List<RuleMatch> matches, String line, int lineNumber) {
        Matcher matcher = ENV_SECRET.matcher(line);
        if (!matcher.find()) {
            return;
        }
        String value = matcher.group(2);
        if (FrontendEvidenceSanitizer.isDummyValue(value)) {
            return;
        }
        matches.add(match(file, lineNumber, line));
    }

    private void addJsMatch(ProjectFile file, List<RuleMatch> matches, String line, int lineNumber) {
        Matcher matcher = JS_SECRET.matcher(line);
        if (!matcher.find()) {
            return;
        }
        String value = matcher.group(2);
        if (FrontendEvidenceSanitizer.isDummyValue(value)) {
            return;
        }
        matches.add(match(file, lineNumber, line));
    }

    private RuleMatch match(ProjectFile file, int lineNumber, String line) {
        return new RuleMatch(
                "HARDCODED_FRONTEND_SECRET",
                RuleCategory.CLIENT_SECRET_EXPOSURE,
                Severity.HIGH,
                file.relativePath(),
                lineNumber,
                "프론트엔드 코드 또는 환경 파일에 클라이언트 비밀 값으로 보이는 문자열이 하드코딩되어 있습니다.",
                "브라우저 번들에 포함되는 값은 비밀로 보호될 수 없습니다. 서버 측 프록시 또는 백엔드 환경변수로 이동하고, 공개 가능한 VITE_ 값만 클라이언트에 노출하세요.",
                FrontendEvidenceSanitizer.maskSecrets(line.strip())
        );
    }
}
