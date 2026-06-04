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
public class UnvalidatedRedirectRule implements VulnerabilityRule {

    private static final Pattern REDIRECT_PARAM = Pattern.compile("(?i)(redirectUrl|returnUrl|next)");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isFrontendSource(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (isRedirectSink(line) && REDIRECT_PARAM.matcher(line).find()) {
                matches.add(new RuleMatch(
                        "UNVALIDATED_REDIRECT",
                        RuleCategory.CLIENT_REDIRECT,
                        Severity.MEDIUM,
                        file.relativePath(),
                        index + 1,
                        "사용자 제어 redirect 파라미터가 클라이언트 리다이렉트에 사용되는 것으로 보입니다. Open Redirect 여부 검토가 필요합니다.",
                        "redirectUrl, returnUrl, next 값은 허용된 내부 경로 또는 신뢰 가능한 origin allowlist로 검증한 뒤 이동해야 합니다.",
                        line.strip()
                ));
            }
        }
        return matches;
    }

    private boolean isRedirectSink(String line) {
        return line.contains("window.location.href")
                || line.contains("location.href")
                || line.contains("window.location.assign");
    }
}

