package com.securedeploy.project.comparison;

import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.repository.ProjectRepository;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.project.dto.ComparedVulnerabilityResponse;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ReviewComparisonService {

    private final ProjectRepository projectRepository;
    private final ReviewRepository reviewRepository;
    private final CurrentUserService currentUserService;

    public ReviewComparisonService(ProjectRepository projectRepository, ReviewRepository reviewRepository,
                                   CurrentUserService currentUserService) {
        this.projectRepository = projectRepository;
        this.reviewRepository = reviewRepository;
        this.currentUserService = currentUserService;
    }

    @Transactional(readOnly = true)
    public ReviewComparisonResponse compareLatest(Long projectId) {
        ProjectEntity project = projectRepository.findById(projectId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "프로젝트를 찾을 수 없습니다."));
        Long userId = currentUserService.currentUserIdOrNull();
        if (project.getUser() != null && userId != null && !project.getUser().getId().equals(userId)) {
            throw new SecureDeployException(HttpStatus.FORBIDDEN, "이 프로젝트에 접근할 권한이 없습니다.");
        }

        List<ReviewEntity> reviews = reviewRepository.findTop2WithVulnerabilitiesByProjectId(projectId);
        if (reviews.size() < 2) {
            return ReviewComparisonResponse.notComparable(projectId, "비교하려면 같은 프로젝트에 최소 2개의 분석 이력이 필요합니다.");
        }

        ReviewEntity latest = reviews.get(0);
        ReviewEntity previous = reviews.get(1);

        var snapshot = latest.getComparison();
        if (snapshot != null && !java.util.Objects.equals(snapshot.baselineReviewId(), previous.getId())) {
            return ReviewComparisonResponse.notComparable(projectId, "기준 이력이 변경되었습니다. 분석 상세의 저장된 변화 보기를 확인하세요.");
        }
        List<ComparedVulnerabilityResponse> resolved = changes(snapshot, com.securedeploy.project.progress.ReviewProgressSnapshot.Change.RESOLVED);
        List<ComparedVulnerabilityResponse> newlyDetected = changes(snapshot, com.securedeploy.project.progress.ReviewProgressSnapshot.Change.NEW);
        List<ComparedVulnerabilityResponse> persisted = changes(snapshot, com.securedeploy.project.progress.ReviewProgressSnapshot.Change.REMAINING);
        return new ReviewComparisonResponse(
                projectId,
                latest.getId(),
                previous.getId(),
                latest.getSecurityScore(),
                previous.getSecurityScore(),
                latest.getSecurityScore() - previous.getSecurityScore(),
                latest.getVulnerabilityCount(),
                previous.getVulnerabilityCount(),
                latest.getVulnerabilityCount() - previous.getVulnerabilityCount(),
                snapshot == null ? "과거 이력에는 비교 범위가 저장되지 않았습니다. 숫자는 참고값이며 해결 여부는 판단할 수 없습니다." : snapshot.message(),
                resolved,
                newlyDetected,
                persisted,
                snapshot
        );
    }

    private List<ComparedVulnerabilityResponse> changes(
            com.securedeploy.project.progress.ReviewProgressSnapshot snapshot,
            com.securedeploy.project.progress.ReviewProgressSnapshot.Change status) {
        if (snapshot == null) return List.of();
        return snapshot.findings().stream().filter(e -> e.status() == status)
                .map(e -> e.after() == null ? e.before() : e.after())
                .map(com.securedeploy.project.progress.ReviewProgressSnapshot.Finding::code)
                .filter(java.util.Objects::nonNull)
                .map(v -> new ComparedVulnerabilityResponse(v.ruleId(), v.category(), v.severity(), v.filePath(),
                        v.line(), v.message(), v.recommendation(), v.evidence(), v.falsePositiveRisk(),
                        v.confidence(), v.analysisNote())).toList();
    }
}
