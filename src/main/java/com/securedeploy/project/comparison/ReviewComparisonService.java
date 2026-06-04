package com.securedeploy.project.comparison;

import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.entity.VulnerabilityEntity;
import com.securedeploy.persistence.repository.ProjectRepository;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.project.dto.ComparedVulnerabilityResponse;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
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

        Map<String, VulnerabilityEntity> latestMap = toComparisonMap(latest.getVulnerabilities());
        Map<String, VulnerabilityEntity> previousMap = toComparisonMap(previous.getVulnerabilities());

        List<ComparedVulnerabilityResponse> resolved = previousMap.entrySet().stream()
                .filter(entry -> !latestMap.containsKey(entry.getKey()))
                .map(Map.Entry::getValue)
                .map(ComparedVulnerabilityResponse::from)
                .toList();

        List<ComparedVulnerabilityResponse> newlyDetected = latestMap.entrySet().stream()
                .filter(entry -> !previousMap.containsKey(entry.getKey()))
                .map(Map.Entry::getValue)
                .map(ComparedVulnerabilityResponse::from)
                .toList();

        List<ComparedVulnerabilityResponse> persisted = latestMap.entrySet().stream()
                .filter(entry -> previousMap.containsKey(entry.getKey()))
                .map(Map.Entry::getValue)
                .map(ComparedVulnerabilityResponse::from)
                .toList();

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
                "최신 분석 결과와 직전 분석 결과를 비교했습니다.",
                resolved,
                newlyDetected,
                persisted
        );
    }

    private Map<String, VulnerabilityEntity> toComparisonMap(List<VulnerabilityEntity> vulnerabilities) {
        return vulnerabilities.stream()
                .collect(Collectors.toMap(
                        this::comparisonKey,
                        Function.identity(),
                        (first, ignored) -> first,
                        LinkedHashMap::new
                ));
    }

    private String comparisonKey(VulnerabilityEntity vulnerability) {
        return normalize(vulnerability.getRuleId())
                + "|" + normalize(vulnerability.getFilePath())
                + "|" + normalize(vulnerability.getEvidence());
    }

    private String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim().replaceAll("\\s+", " ").toLowerCase();
    }
}
