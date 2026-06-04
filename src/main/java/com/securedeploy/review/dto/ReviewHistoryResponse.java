package com.securedeploy.review.dto;

import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.review.model.ReviewSourceType;
import java.time.LocalDateTime;

public record ReviewHistoryResponse(
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

    public static ReviewHistoryResponse from(ReviewEntity entity) {
        return new ReviewHistoryResponse(
                entity.getId(),
                entity.getProject() == null ? null : entity.getProject().getId(),
                entity.getProjectName(),
                entity.getSourceType(),
                entity.getRepositoryUrl(),
                entity.getScannedFileCount(),
                entity.getVulnerabilityCount(),
                entity.getSecurityScore(),
                entity.getDeploymentStatus(),
                entity.getCreatedAt()
        );
    }
}
