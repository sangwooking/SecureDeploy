package com.securedeploy.rule.model;

public record RuleMatch(
        String ruleId,
        RuleCategory category,
        Severity severity,
        String filePath,
        int line,
        String message,
        String recommendation,
        String evidence
) {
}
