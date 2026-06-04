package com.securedeploy.ai.dto;

import java.util.List;

public record AiSecurityRoadmapContent(
        List<AiRoadmapActionResponse> immediateActions,
        List<AiRoadmapActionResponse> thisWeekActions,
        List<AiRoadmapActionResponse> beforeDeploymentChecklist,
        List<AiRoadmapActionResponse> longTermImprovements
) {
}
