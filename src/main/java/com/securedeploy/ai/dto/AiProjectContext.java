package com.securedeploy.ai.dto;

import com.securedeploy.ai.context.AiCodeSnippet;
import com.securedeploy.review.model.ReviewSourceType;
import java.time.LocalDateTime;
import java.util.List;

public record AiProjectContext(
        Long reviewId,
        String projectName,
        ReviewSourceType sourceType,
        String repositoryUrl,
        LocalDateTime createdAt,
        int scannedFileCount,
        int vulnerabilityCount,
        int securityScore,
        String deploymentStatus,
        List<AiVulnerabilityFinding> findings,
        List<AiCodeSnippet> securityConfigSnippets,
        List<AiCodeSnippet> controllerSnippets,
        List<AiCodeSnippet> serviceSnippets,
        List<AiCodeSnippet> repositorySnippets,
        List<AiCodeSnippet> configSnippets,
        List<AiCodeSnippet> clientSnippets
) {

    public List<AiCodeSnippet> allSnippets() {
        return java.util.stream.Stream.of(
                        securityConfigSnippets,
                        controllerSnippets,
                        serviceSnippets,
                        repositorySnippets,
                        configSnippets,
                        clientSnippets
                )
                .flatMap(List::stream)
                .toList();
    }
}
