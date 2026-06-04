package com.securedeploy.ai.dto;

import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;

public record AiRemediationResponse(
        String ruleId,
        Severity severity,
        RuleCategory category,
        String filePath,
        int line,
        String title,
        String beforeExample,
        String afterExample,
        String explanation,
        String verification
) {
}
