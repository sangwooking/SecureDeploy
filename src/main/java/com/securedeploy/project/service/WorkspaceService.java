package com.securedeploy.project.service;

import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.repository.ProjectRepository;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.project.dto.ProjectReviewHistoryResponse;
import com.securedeploy.project.dto.WorkspaceResponse;
import com.securedeploy.risk.model.DeploymentAssessment;
import java.util.Comparator;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class WorkspaceService {
    private final CurrentUserService currentUser;
    private final ProjectRepository projects;
    private final ReviewRepository reviews;

    public WorkspaceService(CurrentUserService currentUser, ProjectRepository projects, ReviewRepository reviews) {
        this.currentUser = currentUser;
        this.projects = projects;
        this.reviews = reviews;
    }

    @Transactional(readOnly = true)
    public WorkspaceResponse getWorkspace() {
        Long owner = currentUser.currentUserId();
        var latest = reviews.findLatestByOwner(owner).stream()
                .collect(Collectors.toMap(r -> r.getProject().getId(), Function.identity()));
        var counts = reviews.countReviewsByOwner(owner).stream().collect(Collectors.toMap(
                ReviewRepository.ProjectReviewCount::getProjectId, ReviewRepository.ProjectReviewCount::getReviewCount));
        var items = projects.findAllByUserIdOrderByUpdatedAtDesc(owner).stream().map(project -> {
            ReviewEntity review = latest.get(project.getId());
            return new WorkspaceResponse.Project(project.getId(), project.getName(), project.getSourceType(),
                    project.getRepositoryUrl(), counts.getOrDefault(project.getId(), 0L), project.getCreatedAt(),
                    project.getUpdatedAt(), review == null ? null : ProjectReviewHistoryResponse.from(review),
                    review == null ? null : WorkspaceResponse.Progress.from(review.getComparison()),
                    project.getGithubRepositoryId(), project.getGithubInstallationId(), project.getPrivateRepository());
        }).sorted(Comparator.comparing((WorkspaceResponse.Project p) -> p.latestReview() == null ? null : p.latestReview().createdAt(),
                Comparator.nullsLast(Comparator.reverseOrder())).thenComparing(WorkspaceResponse.Project::projectId, Comparator.reverseOrder())).toList();
        return new WorkspaceResponse(items.size(),
                items.stream().filter(p -> assessment(p) == DeploymentAssessment.BLOCKED).count(),
                items.stream().filter(p -> assessment(p) == DeploymentAssessment.REVIEW_REQUIRED).count(),
                items.stream().filter(p -> p.latestReview() != null).count(),
                items.stream().filter(p -> assessment(p) == null).count(), items);
    }

    private DeploymentAssessment assessment(WorkspaceResponse.Project project) {
        return project.latestReview() == null || project.latestReview().riskSummary() == null
                ? null : project.latestReview().riskSummary().deploymentAssessment();
    }
}
