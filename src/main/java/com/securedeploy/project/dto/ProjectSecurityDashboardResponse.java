package com.securedeploy.project.dto;

import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.vulnerability.model.VulnerabilityStatus;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public record ProjectSecurityDashboardResponse(
        Long projectId,
        String projectName,
        ReviewSourceType sourceType,
        String repositoryUrl,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        Long latestReviewId,
        LocalDateTime latestAnalyzedAt,
        Integer latestSecurityScore,
        String latestDeploymentStatus,
        Integer latestScannedFileCount,
        Integer latestVulnerabilityCount,
        List<ScoreHistoryItem> scoreHistory,
        Map<Severity, Long> severityCounts,
        Map<VulnerabilityStatus, Long> statusCounts,
        int resolutionRate,
        List<RecentHighRiskVulnerability> recentHighRiskVulnerabilities,
        ComparisonSummary comparisonSummary
) {

    public record ScoreHistoryItem(
            Long reviewId,
            int securityScore,
            int vulnerabilityCount,
            LocalDateTime createdAt
    ) {
    }

    public record RecentHighRiskVulnerability(
            Long vulnerabilityId,
            String ruleId,
            Severity severity,
            RuleCategory category,
            String filePath,
            int line,
            VulnerabilityStatus status,
            String message
    ) {
    }

    public record ComparisonSummary(
            Long previousReviewId,
            Long latestReviewId,
            int scoreDiff,
            int vulnerabilityCountDiff,
            int resolvedCount,
            int newCount,
            int persistedCount,
            String message
    ) {
    }
}
