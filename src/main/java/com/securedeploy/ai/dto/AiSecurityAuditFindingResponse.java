package com.securedeploy.ai.dto;

import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;

public record AiSecurityAuditFindingResponse(
        String title,
        RuleCategory riskArea,
        Severity severity,
        String reasoning,
        String possibleImpact,
        String recommendation,
        AiConfidence confidence
) {
}
