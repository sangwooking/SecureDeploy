package com.securedeploy.project.dto;

import com.securedeploy.persistence.entity.ProjectEntity;
import java.time.LocalDateTime;

public record ProjectDetailResponse(
        Long projectId,
        String name,
        String sourceType,
        String repositoryUrl,
        int reviewCount,
        ProjectReviewHistoryResponse latestReview,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {

    public static ProjectDetailResponse from(ProjectEntity project, ProjectReviewHistoryResponse latestReview) {
        return new ProjectDetailResponse(
                project.getId(),
                project.getName(),
                project.getSourceType().name(),
                project.getRepositoryUrl(),
                project.getReviews().size(),
                latestReview,
                project.getCreatedAt(),
                project.getUpdatedAt()
        );
    }
}
