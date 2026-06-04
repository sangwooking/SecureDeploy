package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class GitHubActionsSecurityRule implements VulnerabilityRule {

    private static final Pattern USES_PATTERN = Pattern.compile("(?i)uses\s*:\s*([^\s#]+)");
    private static final Pattern COMMIT_SHA = Pattern.compile("@[a-f0-9]{40}$");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isGitHubActions(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            addUnpinnedAction(file, matches, line, index + 1);
            if (isSecretEcho(line)) {
                matches.add(new RuleMatch(
                        "GITHUB_ACTIONS_SECRET_ECHO",
                        RuleCategory.CI_CD_SECURITY,
                        Severity.HIGH,
                        file.relativePath(),
                        index + 1,
                        "GitHub Actions workflow에서 secrets 값을 echo로 출력할 수 있는 패턴이 발견되었습니다.",
                        "secret은 로그에 출력하지 말고, 필요한 경우 GitHub masking과 최소 권한 secret scope를 적용하세요.",
                        DevOpsEvidenceSanitizer.maskSecrets(line.strip())
                ));
            }
            if (isCurlPipe(line)) {
                matches.add(new RuleMatch(
                        "GITHUB_ACTIONS_CURL_PIPE",
                        RuleCategory.CI_CD_SECURITY,
                        Severity.HIGH,
                        file.relativePath(),
                        index + 1,
                        "GitHub Actions에서 curl/wget 결과를 바로 shell로 실행하는 패턴이 발견되었습니다.",
                        "설치 스크립트는 체크섬/서명 검증 후 실행하거나 공식 action과 고정 버전을 사용하세요.",
                        line.strip()
                ));
            }
        }
        return matches;
    }


    private boolean isSecretEcho(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        return lower.contains("echo") && lower.contains("${{ secrets.");
    }

    private boolean isCurlPipe(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        return (lower.contains("curl") || lower.contains("wget"))
                && lower.contains("|")
                && (lower.contains("sh") || lower.contains("bash"));
    }

    private void addUnpinnedAction(ProjectFile file, List<RuleMatch> matches, String line, int lineNumber) {
        Matcher matcher = USES_PATTERN.matcher(line);
        if (!matcher.find()) {
            return;
        }
        String action = matcher.group(1).strip();
        String lower = action.toLowerCase(Locale.ROOT);
        if (COMMIT_SHA.matcher(lower).find()) {
            return;
        }
        if (lower.endsWith("@main") || lower.endsWith("@master") || lower.endsWith("@develop") || !lower.contains("@")) {
            matches.add(new RuleMatch(
                    "GITHUB_ACTIONS_UNPINNED",
                    RuleCategory.CI_CD_SECURITY,
                    Severity.MEDIUM,
                    file.relativePath(),
                    lineNumber,
                    "GitHub Actions가 commit hash로 고정되지 않았거나 branch 기반 ref를 사용합니다.",
                    "공급망 공격 위험을 줄이기 위해 action은 검증된 버전 또는 commit SHA로 pinning하세요.",
                    line.strip()
            ));
        }
    }
}
