package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class CorsWildcardRule extends AbstractPatternRule {

    private static final Pattern CORS_PATTERN = Pattern.compile(
            "@CrossOrigin\\s*\\((?:\\s*origins\\s*=\\s*)?[\\{]?\\s*[\\\"']\\*[\\\"']"
    );

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isJava(file)) {
            return List.of();
        }

        return findMatches(
                file,
                "CORS_WILDCARD",
                RuleCategory.CONFIGURATION,
                Severity.MEDIUM,
                "모든 Origin을 허용하는 CORS 설정이 발견되었습니다.",
                "운영 환경에서는 허용할 Origin을 명시적으로 제한해야 합니다.",
                CORS_PATTERN
        );
    }
}
