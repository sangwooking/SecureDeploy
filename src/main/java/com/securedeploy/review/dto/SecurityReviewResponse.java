package com.securedeploy.review.dto;

import java.util.List;

public record SecurityReviewResponse(
        Long reviewId,
        Long projectId,
        String projectName,
        int scannedFileCount,
        int vulnerabilityCount,
        int securityScore,
        String deploymentStatus,
        List<VulnerabilityResultResponse> vulnerabilities
) {

    public SecurityReviewResponse withReviewId(Long reviewId) {
        return withReviewIdAndProjectId(reviewId, projectId);
    }

    public SecurityReviewResponse withReviewIdAndProjectId(Long reviewId, Long projectId) {
        return new SecurityReviewResponse(
                reviewId,
                projectId,
                projectName,
                scannedFileCount,
                vulnerabilityCount,
                securityScore,
                deploymentStatus,
                vulnerabilities
        );
    }
}
