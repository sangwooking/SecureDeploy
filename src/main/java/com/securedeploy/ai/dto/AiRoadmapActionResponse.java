package com.securedeploy.ai.dto;

import java.util.List;

public record AiRoadmapActionResponse(
        String title,
        String description,
        List<String> relatedRuleIds,
        String reason,
        String expectedBenefit
) {
}
