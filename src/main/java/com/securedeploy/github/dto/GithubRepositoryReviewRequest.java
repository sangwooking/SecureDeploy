package com.securedeploy.github.dto;

import jakarta.validation.constraints.NotBlank;

public record GithubRepositoryReviewRequest(
        @NotBlank(message = "GitHub Repository URL은 필수입니다.")
        String repositoryUrl,
        com.securedeploy.review.model.ScanMode scanMode,
        @jakarta.validation.constraints.Pattern(regexp="[a-f0-9]{40}",message="Commit SHA는 40자리 소문자 16진수여야 합니다.") String commitSha
) {
    public GithubRepositoryReviewRequest {
        if (scanMode == null) scanMode = com.securedeploy.review.model.ScanMode.STANDARD;
    }
    public GithubRepositoryReviewRequest(String repositoryUrl,com.securedeploy.review.model.ScanMode mode){this(repositoryUrl,mode,null);}
    public GithubRepositoryReviewRequest(String repositoryUrl) { this(repositoryUrl, null,null); }
}
