package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

abstract class AbstractPatternRule implements VulnerabilityRule {

    protected List<RuleMatch> findMatches(ProjectFile file, String ruleId, RuleCategory category, Severity severity,
                                          String message, String recommendation, Pattern pattern) {
        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();

        for (int index = 0; index < lines.size(); index++) {
            Matcher matcher = pattern.matcher(lines.get(index));
            if (matcher.find()) {
                matches.add(new RuleMatch(
                        ruleId,
                        category,
                        severity,
                        file.relativePath(),
                        index + 1,
                        message,
                        recommendation,
                        abbreviate(matcher.group())
                ));
            }
        }

        return matches;
    }

    protected String abbreviate(String text) {
        String normalized = text.strip();
        if (normalized.length() <= 140) {
            return normalized;
        }
        return normalized.substring(0, 137) + "...";
    }
}
