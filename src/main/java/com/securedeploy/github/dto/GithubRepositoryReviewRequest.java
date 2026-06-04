package com.securedeploy.github.dto;

import jakarta.validation.constraints.NotBlank;

public record GithubRepositoryReviewRequest(
        @NotBlank(message = "GitHub Repository URL은 필수입니다.")
        String repositoryUrl
) {
}
