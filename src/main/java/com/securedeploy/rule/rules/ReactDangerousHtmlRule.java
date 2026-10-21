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
                        "먼저 출력값의 출처와 기존 보호 처리를 확인하세요. 일반 텍스트라면 JSX 문자열 출력으로 바꾸고, 외부 HTML이 꼭 필요한 경우에만 검증된 정제 처리를 검토하세요. 정상 입력과 허용하지 않을 HTML을 로컬 테스트한 뒤 재검사하세요.",
                        line.strip()
                ));
            }
        }
        return matches;
    }
}
