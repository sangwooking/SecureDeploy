package com.securedeploy.project.dto;

import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.review.model.ReviewSourceType;
import java.time.LocalDateTime;

public record ProjectResponse(
        Long projectId,
        String name,
        ReviewSourceType sourceType,
        String repositoryUrl,
        int reviewCount,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {

    public static ProjectResponse from(ProjectEntity project) {
        return new ProjectResponse(
                project.getId(),
                project.getName(),
                project.getSourceType(),
                project.getRepositoryUrl(),
                project.getReviews().size(),
                project.getCreatedAt(),
                project.getUpdatedAt()
        );
    }
}
