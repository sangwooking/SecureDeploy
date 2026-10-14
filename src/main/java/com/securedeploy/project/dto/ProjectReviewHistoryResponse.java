package com.securedeploy.project.dto;

import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.review.model.ReviewSourceType;
import java.time.LocalDateTime;

public record ProjectReviewHistoryResponse(
        Long reviewId,
        Long projectId,
        String projectName,
        ReviewSourceType sourceType,
        String repositoryUrl,
        int scannedFileCount,
        int vulnerabilityCount,
        int securityScore,
        String deploymentStatus,
        LocalDateTime createdAt,
        com.securedeploy.project.progress.ReviewProgressSnapshot.Assessment riskSummary,
        boolean comparisonAvailable,
        Long findingCount
) {

    public static ProjectReviewHistoryResponse from(ReviewEntity review) {
        Long projectId = review.getProject() == null ? null : review.getProject().getId();
        return new ProjectReviewHistoryResponse(
                review.getId(),
                projectId,
                review.getProjectName(),
                review.getSourceType(),
                review.getRepositoryUrl(),
                review.getScannedFileCount(),
                review.getVulnerabilityCount(),
                review.getSecurityScore(),
                review.getDeploymentStatus(),
                review.getCreatedAt(),
                com.securedeploy.project.progress.ProgressComparisonEngine.assessment(review),
                review.getComparison() != null && review.getComparison().baselineReviewId() != null,
                review.getRiskAssessment() == null ? null : review.getRiskAssessment().prioritySummary().values().stream().mapToLong(Long::longValue).sum()
        );
    }
}
