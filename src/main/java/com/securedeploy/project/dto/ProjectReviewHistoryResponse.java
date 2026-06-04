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
        LocalDateTime createdAt
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
                review.getCreatedAt()
        );
    }
}
