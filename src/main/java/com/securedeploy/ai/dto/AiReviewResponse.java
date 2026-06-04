package com.securedeploy.ai.dto;

public record AiReviewResponse(
        String ruleId,
        String title,
        String description,
        String riskExplanation,
        String attackScenario,
        String recommendation,
        String priority
) {
}
