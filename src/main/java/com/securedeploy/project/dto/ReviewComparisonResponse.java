package com.securedeploy.project.dto;

import java.util.List;

public record ReviewComparisonResponse(
        Long projectId,
        Long latestReviewId,
        Long previousReviewId,
        int latestSecurityScore,
        int previousSecurityScore,
        int scoreDiff,
        int latestVulnerabilityCount,
        int previousVulnerabilityCount,
        int vulnerabilityCountDiff,
        String message,
        List<ComparedVulnerabilityResponse> resolvedVulnerabilities,
        List<ComparedVulnerabilityResponse> newVulnerabilities,
        List<ComparedVulnerabilityResponse> persistedVulnerabilities
) {

    public static ReviewComparisonResponse notComparable(Long projectId, String message) {
        return new ReviewComparisonResponse(
                projectId,
                null,
                null,
                0,
                0,
                0,
                0,
                0,
                0,
                message,
                List.of(),
                List.of(),
                List.of()
        );
    }
}
