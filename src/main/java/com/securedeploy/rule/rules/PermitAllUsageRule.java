package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class PermitAllUsageRule extends AbstractPatternRule {

    private static final Pattern PERMIT_ALL_PATTERN = Pattern.compile("\\.permitAll\\s*\\(\\s*\\)");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isJava(file)) {
            return List.of();
        }

        return findMatches(
                file,
                "PERMIT_ALL_USAGE",
                RuleCategory.AUTHORIZATION,
                Severity.MEDIUM,
                "permitAll() 사용이 발견되었습니다.",
                "공개가 필요한 엔드포인트인지 확인하고, 필요한 경우 인증/인가 정책을 적용해야 합니다.",
                PERMIT_ALL_PATTERN
        );
    }
}
