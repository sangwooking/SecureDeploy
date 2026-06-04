package com.securedeploy.ai.dto;

import java.util.List;

public record AiComparisonInsightResponse(
        Long projectId,
        Long latestReviewId,
        Long previousReviewId,
        String overallInsight,
        String improvementSummary,
        String remainingRiskSummary,
        String newRiskSummary,
        String deploymentReadinessOpinion,
        List<String> nextRecommendedActions,
        AiUsageResponse usage
) {

    public AiComparisonInsightResponse withUsage(AiUsageResponse usage) {
        return new AiComparisonInsightResponse(
                projectId,
                latestReviewId,
                previousReviewId,
                overallInsight,
                improvementSummary,
                remainingRiskSummary,
                newRiskSummary,
                deploymentReadinessOpinion,
                nextRecommendedActions,
                usage
        );
    }
}
