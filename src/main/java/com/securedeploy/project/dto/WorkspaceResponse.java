package com.securedeploy.project.dto;

import com.securedeploy.project.progress.ReviewProgressSnapshot;
import com.securedeploy.review.model.ReviewSourceType;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public record WorkspaceResponse(long projectCount, long blockedProjectCount, long reviewRequiredProjectCount,
        long analyzedProjectCount, long unassessedProjectCount, List<Project> projects) {
    public record Project(Long projectId, String name, ReviewSourceType sourceType, String repositoryUrl,
            long reviewCount, LocalDateTime createdAt, LocalDateTime updatedAt,
            ProjectReviewHistoryResponse latestReview, Progress latestProgress) { }
    public record Progress(ReviewProgressSnapshot.Status status, Long baselineReviewId,
            Map<ReviewProgressSnapshot.Change, Long> counts, String message) {
        public static Progress from(ReviewProgressSnapshot snapshot) {
            return snapshot == null ? null : new Progress(snapshot.status(), snapshot.baselineReviewId(),
                    snapshot.counts(), snapshot.message());
        }
    }
}
