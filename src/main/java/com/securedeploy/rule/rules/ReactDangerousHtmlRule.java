package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class ReactDangerousHtmlRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isFrontendSource(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (line.contains("dangerouslySetInnerHTML")) {
                matches.add(new RuleMatch(
                        "REACT_DANGEROUS_HTML",
                        RuleCategory.CLIENT_XSS,
                        Severity.HIGH,
                        file.relativePath(),
                        index + 1,
                        "React에서 dangerouslySetInnerHTML 사용이 발견되었습니다. 사용자 입력이 포함될 경우 XSS 위험이 있습니다.",
                        "HTML 삽입이 꼭 필요하다면 DOMPurify 같은 검증된 sanitizer를 적용하고, 사용자 입력을 직접 렌더링하지 않도록 제한해야 합니다.",
                        line.strip()
                ));
            }
        }
        return matches;
    }
}
