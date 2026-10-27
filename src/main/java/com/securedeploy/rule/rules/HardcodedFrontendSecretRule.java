package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
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

    private static final Pattern ENV_SECRET = Pattern.compile("(?i)^\\h*(?:export\\h+)?\\b([A-Z0-9_]*(?:API_KEY|SECRET|TOKEN)[A-Z0-9_]*)\\h*=\\h*(?:\"([^\"\\r\\n]*)\"|'([^'\\r\\n]*)'|([^\\s#;]+))\\h*(?:#.*)?$");
    private static final Pattern JS_SECRET = Pattern.compile("(?i)(api[_-]?key|secret|token|accessToken|refreshToken)[\"']?\\s*[:=]\\s*[\"']([^\"']{8,})[\"']");
    private static final Pattern CREDENTIAL = Pattern.compile("^(?:sb_secret_[A-Za-z0-9_-]{24,}|sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{24,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)$");
    private static final Pattern PUBLIC_SUPABASE_KEY = Pattern.compile("^sb_publishable_[A-Za-z0-9_-]{24,}$");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isFrontendSecretCandidate(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (file.type() == ProjectFileType.ENV || file.type() == ProjectFileType.ENV_FILE)
                addEnvMatch(file, matches, line, index + 1);
            else addJsMatch(file, matches, line, index + 1);
        }
        return matches;
    }

    private void addEnvMatch(ProjectFile file, List<RuleMatch> matches, String line, int lineNumber) {
        Matcher matcher = ENV_SECRET.matcher(line);
        if (!matcher.find()) {
            return;
        }
        String value = matcher.group(2) != null ? matcher.group(2) : matcher.group(3) != null ? matcher.group(3) : matcher.group(4);
        if ((FrontendEvidenceSanitizer.isDummyValue(value) && !CREDENTIAL.matcher(value).matches()) || !credentialCandidate(value)) {
            return;
        }
        matches.add(match(file, lineNumber, line));
    }

    static boolean credentialCandidate(String value) {
        if (PUBLIC_SUPABASE_KEY.matcher(value).matches()) return false;
        if (CREDENTIAL.matcher(value).matches()) return true;
        if (value.length() < 32 || value.startsWith("${") || value.startsWith("http://") || value.startsWith("https://")
                || value.startsWith("pk_live_") || value.startsWith("pk_test_")
                || value.matches("(?i)[a-f0-9]{32,128}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")) return false;
        var counts = new java.util.HashMap<Character, Integer>();
        for (int i = 0; i < value.length(); i++) counts.merge(value.charAt(i), 1, Integer::sum);
        double entropy = 0;
        for (int count : counts.values()) {
            double probability = (double)count / value.length();
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return counts.size() >= 12 && entropy >= 3.5;
    }

    private void addJsMatch(ProjectFile file, List<RuleMatch> matches, String line, int lineNumber) {
        Matcher matcher = JS_SECRET.matcher(line);
        if (!matcher.find()) {
            return;
        }
        String value = matcher.group(2);
        if (PUBLIC_SUPABASE_KEY.matcher(value).matches() || FrontendEvidenceSanitizer.isDummyValue(value)) {
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
