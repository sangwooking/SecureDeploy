package com.securedeploy.github.dto;

import jakarta.validation.constraints.NotBlank;

public record GithubRepositoryReviewRequest(
        @NotBlank(message = "GitHub Repository URL은 필수입니다.")
        String repositoryUrl,
        com.securedeploy.review.model.ScanMode scanMode
) {
    public GithubRepositoryReviewRequest {
        if (scanMode == null) scanMode = com.securedeploy.review.model.ScanMode.STANDARD;
    }
    public GithubRepositoryReviewRequest(String repositoryUrl) { this(repositoryUrl, null); }
}
