package com.securedeploy.persistence.service;

import com.securedeploy.ai.context.AiCodeSnippet;
import com.securedeploy.auth.service.ReviewAccessService;
import com.securedeploy.ai.context.SnippetGroup;
import com.securedeploy.ai.context.SnippetType;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.entity.ReviewSnippetEntity;
import com.securedeploy.persistence.entity.VulnerabilityEntity;
import com.securedeploy.persistence.repository.ProjectRepository;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.review.dto.ReviewHistoryResponse;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.review.model.ReviewSourceType;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ReviewPersistenceService {

    private final ReviewRepository reviewRepository;
    private final ProjectRepository projectRepository;
    private final ReviewAccessService reviewAccessService;

    public ReviewPersistenceService(ReviewRepository reviewRepository, ProjectRepository projectRepository,
                                    ReviewAccessService reviewAccessService) {
        this.reviewRepository = reviewRepository;
        this.projectRepository = projectRepository;
        this.reviewAccessService = reviewAccessService;
    }

    @Transactional
    public SecurityReviewResponse saveReview(SecurityReviewResponse response, ReviewSourceType sourceType,
                                             String repositoryUrl, SnippetGroup snippetGroup) {
        return saveReview(null, response, sourceType, repositoryUrl, snippetGroup);
    }

    @Transactional
    public SecurityReviewResponse saveReview(ProjectEntity project, SecurityReviewResponse response, ReviewSourceType sourceType,
                                             String repositoryUrl, SnippetGroup snippetGroup) {
        ReviewEntity review = new ReviewEntity(
                response.projectName(),
                sourceType,
                repositoryUrl,
                response.scannedFileCount(),
                response.vulnerabilityCount(),
                response.securityScore(),
                response.deploymentStatus()
        );

        if (project != null) {
            ProjectEntity managedProject = projectRepository.findById(project.getId())
                    .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "프로젝트를 찾을 수 없습니다."));
            managedProject.touch();
            review.assignProject(managedProject);
        }

        response.vulnerabilities().stream()
                .map(this::toEntity)
                .forEach(review::addVulnerability);

        addSnippets(review, snippetGroup == null ? SnippetGroup.empty() : snippetGroup);

        ReviewEntity savedReview = reviewRepository.save(review);
        return findReviewDetail(savedReview.getId());
    }

    @Transactional(readOnly = true)
    public List<ReviewHistoryResponse> findReviewHistories() {
        return reviewRepository.findAllByOrderByCreatedAtDesc().stream()
                .map(ReviewHistoryResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ReviewHistoryResponse> findReviewHistories(Long userId) {
        if (userId == null) {
            return findReviewHistories();
        }
        return reviewRepository.findAllAccessibleByUserIdOrderByCreatedAtDesc(userId).stream()
                .map(ReviewHistoryResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public SecurityReviewResponse findReviewDetail(Long reviewId) {
        ReviewEntity review = reviewRepository.findByIdWithVulnerabilities(reviewId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "분석 이력을 찾을 수 없습니다."));

        return toResponse(review);
    }

    @Transactional(readOnly = true)
    public SecurityReviewResponse findReviewDetail(Long reviewId, Long userId) {
        ReviewEntity review = reviewAccessService.findAccessibleReviewWithVulnerabilities(reviewId, "분석 이력을 찾을 수 없습니다.");
        return toResponse(review);
    }

    private SecurityReviewResponse toResponse(ReviewEntity review) {
        return new SecurityReviewResponse(
                review.getId(),
                review.getProject() == null ? null : review.getProject().getId(),
                review.getProjectName(),
                review.getScannedFileCount(),
                review.getVulnerabilityCount(),
                review.getSecurityScore(),
                review.getDeploymentStatus(),
                review.getVulnerabilities().stream()
                        .map(VulnerabilityResultResponse::from)
                        .toList()
        );
    }

    private void addSnippets(ReviewEntity review, SnippetGroup snippetGroup) {
        addSnippets(review, SnippetType.SECURITY_CONFIG, snippetGroup.securityConfigSnippets());
        addSnippets(review, SnippetType.CONTROLLER, snippetGroup.controllerSnippets());
        addSnippets(review, SnippetType.SERVICE, snippetGroup.serviceSnippets());
        addSnippets(review, SnippetType.REPOSITORY, snippetGroup.repositorySnippets());
        addSnippets(review, SnippetType.CONFIG, snippetGroup.configSnippets());
        addSnippets(review, SnippetType.CLIENT, snippetGroup.clientSnippets());
    }

    private void addSnippets(ReviewEntity review, SnippetType type, List<AiCodeSnippet> snippets) {
        snippets.stream()
                .map(snippet -> new ReviewSnippetEntity(type, snippet.filePath(), snippet.content()))
                .forEach(review::addSnippet);
    }

    private VulnerabilityEntity toEntity(VulnerabilityResultResponse vulnerability) {
        return new VulnerabilityEntity(
                vulnerability.ruleId(),
                vulnerability.category(),
                vulnerability.severity(),
                vulnerability.filePath(),
                vulnerability.line(),
                vulnerability.message(),
                vulnerability.recommendation(),
                vulnerability.evidence()
        );
    }
}
