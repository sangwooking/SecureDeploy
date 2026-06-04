package com.securedeploy.ai.dto;

import java.time.LocalDateTime;
import java.util.List;

public record AiSecurityRoadmapResponse(
        Long reviewId,
        LocalDateTime generatedAt,
        List<AiRoadmapActionResponse> immediateActions,
        List<AiRoadmapActionResponse> thisWeekActions,
        List<AiRoadmapActionResponse> beforeDeploymentChecklist,
        List<AiRoadmapActionResponse> longTermImprovements,
        AiUsageResponse usage
) {
}
