package com.securedeploy.review.dto;

import java.util.List;
import com.securedeploy.sca.model.ScaResult;
import com.fasterxml.jackson.annotation.JsonProperty;

public record SecurityReviewResponse(
        Long reviewId,
        Long projectId,
        String projectName,
        int scannedFileCount,
        int vulnerabilityCount,
        int securityScore,
        String deploymentStatus,
        List<VulnerabilityResultResponse> vulnerabilities,
        ScaResult sca
) {
    @JsonProperty("deploymentAssessmentScope")
    public String deploymentAssessmentScope() {
        return "RULE_ENGINE_ONLY";
    }

    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
                                  int vulnerabilityCount, int securityScore, String deploymentStatus,
                                  List<VulnerabilityResultResponse> vulnerabilities) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore,
                deploymentStatus, vulnerabilities, null);
    }

    public SecurityReviewResponse withSca(ScaResult result) {
        return new SecurityReviewResponse(reviewId, projectId, projectName, scannedFileCount,
                vulnerabilityCount, securityScore, deploymentStatus, vulnerabilities, result);
    }

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
                vulnerabilities,
                sca
        );
    }
}
