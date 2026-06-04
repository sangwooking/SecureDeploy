package com.securedeploy.project.controller;

import com.securedeploy.ai.dto.AiComparisonInsightResponse;
import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.ai.service.AiReviewService;
import com.securedeploy.github.dto.GithubRepositoryReviewRequest;
import com.securedeploy.project.comparison.ReviewComparisonService;
import com.securedeploy.project.dto.ProjectDetailResponse;
import com.securedeploy.project.dto.ProjectResponse;
import com.securedeploy.project.dto.ProjectReviewHistoryResponse;
import com.securedeploy.project.dto.ProjectSecurityDashboardResponse;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import com.securedeploy.project.service.ProjectDashboardService;
import com.securedeploy.project.service.ProjectService;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.service.SecurityReviewFacade;
import com.securedeploy.vulnerability.dto.VulnerabilityStatusSummaryResponse;
import com.securedeploy.vulnerability.service.VulnerabilityStatusService;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/projects")
public class ProjectController {

    private final ProjectService projectService;
    private final CurrentUserService currentUserService;
    private final SecurityReviewFacade securityReviewFacade;
    private final ProjectDashboardService projectDashboardService;
    private final ReviewComparisonService reviewComparisonService;
    private final AiReviewService aiReviewService;
    private final VulnerabilityStatusService vulnerabilityStatusService;

    public ProjectController(ProjectService projectService, CurrentUserService currentUserService, SecurityReviewFacade securityReviewFacade,
                             ProjectDashboardService projectDashboardService, ReviewComparisonService reviewComparisonService,
                             AiReviewService aiReviewService, VulnerabilityStatusService vulnerabilityStatusService) {
        this.projectService = projectService;
        this.currentUserService = currentUserService;
        this.securityReviewFacade = securityReviewFacade;
        this.projectDashboardService = projectDashboardService;
        this.reviewComparisonService = reviewComparisonService;
        this.aiReviewService = aiReviewService;
        this.vulnerabilityStatusService = vulnerabilityStatusService;
    }

    @GetMapping
    public ResponseEntity<List<ProjectResponse>> findProjects() {
        return ResponseEntity.ok(projectService.findProjectsByUser(currentUserService.currentUserId()));
    }

    @GetMapping("/{projectId}")
    public ResponseEntity<ProjectDetailResponse> findProjectDetail(@PathVariable Long projectId) {
        return ResponseEntity.ok(projectService.findProjectDetail(projectId, currentUserService.currentUserId()));
    }


    @GetMapping("/{projectId}/dashboard")
    public ResponseEntity<ProjectSecurityDashboardResponse> findProjectDashboard(@PathVariable Long projectId) {
        return ResponseEntity.ok(projectDashboardService.getDashboard(projectId, currentUserService.currentUserId()));
    }

    @GetMapping("/{projectId}/reviews")
    public ResponseEntity<List<ProjectReviewHistoryResponse>> findProjectReviews(@PathVariable Long projectId) {
        return ResponseEntity.ok(projectService.findProjectReviews(projectId, currentUserService.currentUserId()));
    }

    @GetMapping("/{projectId}/vulnerabilities/status-summary")
    public ResponseEntity<VulnerabilityStatusSummaryResponse> findVulnerabilityStatusSummary(@PathVariable Long projectId) {
        return ResponseEntity.ok(vulnerabilityStatusService.findProjectStatusSummary(projectId));
    }

    @GetMapping("/{projectId}/reviews/compare-latest")
    public ResponseEntity<ReviewComparisonResponse> compareLatestReviews(@PathVariable Long projectId) {
        return ResponseEntity.ok(reviewComparisonService.compareLatest(projectId));
    }

    @GetMapping("/{projectId}/reviews/compare-latest/ai")
    public ResponseEntity<AiComparisonInsightResponse> compareLatestReviewsWithAi(@PathVariable Long projectId) {
        return ResponseEntity.ok(aiReviewService.generateComparisonInsight(reviewComparisonService.compareLatest(projectId)));
    }

    @PostMapping(value = "/{projectId}/reviews/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<SecurityReviewResponse> uploadProjectReview(@PathVariable Long projectId,
                                                                      @RequestPart("file") MultipartFile file) {
        return ResponseEntity.ok(securityReviewFacade.reviewUploadedZip(projectId, file));
    }

    @PostMapping(value = "/{projectId}/reviews/github", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SecurityReviewResponse> reviewProjectGitHubRepository(@PathVariable Long projectId,
                                                                                @Valid @RequestBody GithubRepositoryReviewRequest request) {
        return ResponseEntity.ok(securityReviewFacade.reviewGitHubRepository(projectId, request.repositoryUrl()));
    }
}
