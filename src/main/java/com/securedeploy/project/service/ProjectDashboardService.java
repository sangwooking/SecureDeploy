package com.securedeploy.project.service;

import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.entity.VulnerabilityEntity;
import com.securedeploy.persistence.repository.ProjectRepository;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.persistence.repository.VulnerabilityRepository;
import com.securedeploy.project.comparison.ReviewComparisonService;
import com.securedeploy.project.dto.ProjectSecurityDashboardResponse;
import com.securedeploy.project.dto.ProjectSecurityDashboardResponse.ComparisonSummary;
import com.securedeploy.project.dto.ProjectSecurityDashboardResponse.RecentHighRiskVulnerability;
import com.securedeploy.project.dto.ProjectSecurityDashboardResponse.ScoreHistoryItem;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.vulnerability.model.VulnerabilityStatus;
import com.securedeploy.global.error.SecureDeployException;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProjectDashboardService {

    private static final int HIGH_RISK_LIMIT = 5;

    private final ProjectRepository projectRepository;
    private final ReviewRepository reviewRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final ReviewComparisonService reviewComparisonService;

    public ProjectDashboardService(ProjectRepository projectRepository, ReviewRepository reviewRepository,
                                   VulnerabilityRepository vulnerabilityRepository, ReviewComparisonService reviewComparisonService) {
        this.projectRepository = projectRepository;
        this.reviewRepository = reviewRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.reviewComparisonService = reviewComparisonService;
    }

    @Transactional(readOnly = true)
    public ProjectSecurityDashboardResponse getDashboard(Long projectId) {
        return getDashboard(projectId, null);
    }

    @Transactional(readOnly = true)
    public ProjectSecurityDashboardResponse getDashboard(Long projectId, Long userId) {
        ProjectEntity project = projectRepository.findById(projectId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "프로젝트를 찾을 수 없습니다."));
        if (project.getUser() != null && userId != null && !project.getUser().getId().equals(userId)) {
            throw new SecureDeployException(HttpStatus.FORBIDDEN, "이 프로젝트에 접근할 권한이 없습니다.");
        }

        List<ReviewEntity> reviewsDesc = reviewRepository.findAllWithVulnerabilitiesByProjectIdOrderByCreatedAtDesc(projectId);
        ReviewEntity latestReview = reviewsDesc.isEmpty() ? null : reviewsDesc.get(0);
        List<ScoreHistoryItem> scoreHistory = reviewsDesc.stream()
                .sorted(Comparator.comparing(ReviewEntity::getCreatedAt))
                .map(review -> new ScoreHistoryItem(
                        review.getId(),
                        review.getSecurityScore(),
                        review.getVulnerabilityCount(),
                        review.getCreatedAt()
                ))
                .toList();

        List<VulnerabilityEntity> projectVulnerabilities = vulnerabilityRepository.findAllByReviewProjectId(projectId);
        Map<Severity, Long> severityCounts = countSeverity(latestReview);
        Map<VulnerabilityStatus, Long> statusCounts = countStatus(projectVulnerabilities);
        long total = projectVulnerabilities.size();
        long resolved = statusCounts.get(VulnerabilityStatus.RESOLVED);
        int resolutionRate = total == 0 ? 0 : (int) Math.round((resolved * 100.0) / total);

        return new ProjectSecurityDashboardResponse(
                project.getId(),
                project.getName(),
                project.getSourceType(),
                project.getRepositoryUrl(),
                project.getCreatedAt(),
                project.getUpdatedAt(),
                latestReview == null ? null : latestReview.getId(),
                latestReview == null ? null : latestReview.getCreatedAt(),
                latestReview == null ? null : latestReview.getSecurityScore(),
                latestReview == null ? null : latestReview.getDeploymentStatus(),
                latestReview == null ? null : latestReview.getScannedFileCount(),
                latestReview == null ? null : latestReview.getVulnerabilityCount(),
                scoreHistory,
                severityCounts,
                statusCounts,
                resolutionRate,
                recentHighRiskVulnerabilities(latestReview),
                comparisonSummary(projectId)
        );
    }

    private Map<Severity, Long> countSeverity(ReviewEntity latestReview) {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            counts.put(severity, 0L);
        }

        if (latestReview == null) {
            return counts;
        }

        for (VulnerabilityEntity vulnerability : latestReview.getVulnerabilities()) {
            counts.compute(vulnerability.getSeverity(), (ignored, count) -> count == null ? 1L : count + 1L);
        }
        return counts;
    }

    private Map<VulnerabilityStatus, Long> countStatus(List<VulnerabilityEntity> vulnerabilities) {
        Map<VulnerabilityStatus, Long> counts = new EnumMap<>(VulnerabilityStatus.class);
        for (VulnerabilityStatus status : VulnerabilityStatus.values()) {
            counts.put(status, 0L);
        }

        for (VulnerabilityEntity vulnerability : vulnerabilities) {
            VulnerabilityStatus status = vulnerability.getStatus() == null ? VulnerabilityStatus.UNCHECKED : vulnerability.getStatus();
            counts.compute(status, (ignored, count) -> count == null ? 1L : count + 1L);
        }
        return counts;
    }

    private List<RecentHighRiskVulnerability> recentHighRiskVulnerabilities(ReviewEntity latestReview) {
        if (latestReview == null) {
            return List.of();
        }

        return latestReview.getVulnerabilities().stream()
                .sorted(Comparator.comparingInt((VulnerabilityEntity vulnerability) -> severityRank(vulnerability.getSeverity()))
                        .thenComparing(VulnerabilityEntity::getFilePath)
                        .thenComparingInt(VulnerabilityEntity::getLine))
                .limit(HIGH_RISK_LIMIT)
                .map(vulnerability -> new RecentHighRiskVulnerability(
                        vulnerability.getId(),
                        vulnerability.getRuleId(),
                        vulnerability.getSeverity(),
                        vulnerability.getCategory(),
                        vulnerability.getFilePath(),
                        vulnerability.getLine(),
                        vulnerability.getStatus() == null ? VulnerabilityStatus.UNCHECKED : vulnerability.getStatus(),
                        vulnerability.getMessage()
                ))
                .toList();
    }

    private int severityRank(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
        };
    }

    private ComparisonSummary comparisonSummary(Long projectId) {
        ReviewComparisonResponse comparison = reviewComparisonService.compareLatest(projectId);
        if (comparison.latestReviewId() == null || comparison.previousReviewId() == null) {
            return new ComparisonSummary(
                    null,
                    null,
                    0,
                    0,
                    0,
                    0,
                    0,
                    comparison.message()
            );
        }

        return new ComparisonSummary(
                comparison.previousReviewId(),
                comparison.latestReviewId(),
                comparison.scoreDiff(),
                comparison.vulnerabilityCountDiff(),
                comparison.resolvedVulnerabilities().size(),
                comparison.newVulnerabilities().size(),
                comparison.persistedVulnerabilities().size(),
                comparison.message()
        );
    }
}
