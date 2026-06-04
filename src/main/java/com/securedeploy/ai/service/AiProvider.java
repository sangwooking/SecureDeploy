package com.securedeploy.ai.service;

import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.dto.AiComparisonInsightResponse;
import com.securedeploy.ai.dto.AiPriorityItemResponse;
import com.securedeploy.ai.dto.AiProjectContext;
import com.securedeploy.ai.dto.AiProjectSummaryContent;
import com.securedeploy.ai.dto.AiRemediationResponse;
import com.securedeploy.ai.dto.AiReviewRequest;
import com.securedeploy.ai.dto.AiReviewResponse;
import com.securedeploy.ai.dto.AiSecurityAuditFindingResponse;
import com.securedeploy.ai.dto.AiSecurityRoadmapContent;
import com.securedeploy.ai.usage.AiTokenUsage;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import java.util.List;
import java.util.Optional;

public interface AiProvider {

    AiProviderType providerType();

    default boolean isAvailable() {
        return true;
    }

    default Optional<AiTokenUsage> consumeLastTokenUsage() {
        return Optional.empty();
    }

    AiReviewResponse generateVulnerabilityReview(AiReviewRequest request, String prompt);

    AiProjectSummaryContent generateProjectSummary(AiProjectContext context, String prompt);

    List<AiRemediationResponse> generateRemediationSuggestions(AiProjectContext context, String prompt);

    List<AiSecurityAuditFindingResponse> generateSecurityAudit(AiProjectContext context, String prompt);

    AiComparisonInsightResponse generateComparisonInsight(ReviewComparisonResponse comparison, String prompt);

    List<AiPriorityItemResponse> generatePriorities(AiProjectContext context, String prompt);

    AiSecurityRoadmapContent generateSecurityRoadmap(AiProjectContext context, String prompt);
}
