package com.securedeploy.ai.dto;

import com.securedeploy.rule.model.Severity;

public record AiPriorityItemResponse(
        int rank,
        String ruleId,
        String title,
        Severity severity,
        String reason,
        String expectedImpact,
        String fixDifficulty,
        String recommendedAction,
        String urgency
) {
}
