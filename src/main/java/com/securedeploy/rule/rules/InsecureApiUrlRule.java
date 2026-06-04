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
public class InsecureApiUrlRule implements VulnerabilityRule {

    private static final Pattern HTTP_URL = Pattern.compile("(?i)(?:VITE_[A-Z0-9_]*API[A-Z0-9_]*\s*=\s*)?http://([^\s\"']+)");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isFrontendSource(file) && !RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            Matcher matcher = HTTP_URL.matcher(line);
            if (matcher.find()) {
                String host = matcher.group(1).toLowerCase();
                if (host.startsWith("localhost") || host.startsWith("127.0.0.1")) {
                    continue;
                }
                matches.add(new RuleMatch(
                        "INSECURE_API_URL",
                        RuleCategory.FRONTEND_SECURITY,
                        Severity.MEDIUM,
                        file.relativePath(),
                        index + 1,
                        "프론트엔드 설정 또는 코드에서 http:// 기반 API URL이 발견되었습니다. 운영 환경에서 평문 통신 위험이 있습니다.",
                        "운영 API URL은 HTTPS를 사용하고, 환경별 API base URL을 배포 환경에서 안전하게 주입하세요.",
                        FrontendEvidenceSanitizer.maskSecrets(line.strip())
                ));
            }
        }
        return matches;
    }
}
