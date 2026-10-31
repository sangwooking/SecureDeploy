package com.securedeploy.github.app;

import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.service.SecurityReviewFacade;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
public class ConnectedGitHubReviewController {
    private final SecurityReviewFacade reviews;
    public ConnectedGitHubReviewController(SecurityReviewFacade reviews) { this.reviews = reviews; }
    @PostMapping("/api/reviews/github/connected")
    public SecurityReviewResponse analyze(@Valid @RequestBody GitHubAppDtos.Analyze request) {
        return request.commitSha()==null?reviews.reviewConnectedGitHub(null,request.installationId(),request.repositoryId(),request.scanMode()):reviews.reviewConnectedGitHub(null,request.installationId(),request.repositoryId(),request.scanMode(),request.commitSha());
    }
    @PostMapping("/api/projects/{projectId}/reviews/github/connected")
    public SecurityReviewResponse rescan(@PathVariable Long projectId, @Valid @RequestBody GitHubAppDtos.Analyze request) {
        return request.commitSha()==null?reviews.reviewConnectedGitHub(projectId,request.installationId(),request.repositoryId(),request.scanMode()):reviews.reviewConnectedGitHub(projectId,request.installationId(),request.repositoryId(),request.scanMode(),request.commitSha());
    }
}
