package com.securedeploy.ai.dto;

import java.time.LocalDateTime;
import java.util.List;

public record AiProjectSummaryResponse(
        Long reviewId,
        LocalDateTime generatedAt,
        String overallSecurityStatus,
        String mostRiskyArea,
        List<String> priorityFixes,
        List<String> preDeploymentActions,
        String deploymentOpinion,
        AiUsageResponse usage
) {

    public static AiProjectSummaryResponse from(Long reviewId, LocalDateTime generatedAt,
                                                AiProjectSummaryContent content, AiUsageResponse usage) {
        return new AiProjectSummaryResponse(
                reviewId,
                generatedAt,
                content.overallSecurityStatus(),
                content.mostRiskyArea(),
                content.priorityFixes(),
                content.preDeploymentActions(),
                content.deploymentOpinion(),
                usage
        );
    }
}
