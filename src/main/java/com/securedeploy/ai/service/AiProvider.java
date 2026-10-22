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
    default com.securedeploy.editing.WorkspacePatch.Output generateWorkspacePatch(com.securedeploy.editing.WorkspacePatch.Prompt prompt) {
        throw new UnsupportedOperationException("Workspace patch generation is unavailable");
    }

    default List<com.securedeploy.ai.semantic.SemanticCandidate.Proposal> generateSemanticReview(
            List<com.securedeploy.ai.semantic.SecuritySlice> slices, com.securedeploy.ai.semantic.SemanticPrompt prompt) {
        throw new UnsupportedOperationException("Semantic review is not available");
    }

    AiProviderType providerType();

    default java.util.Map<String, com.securedeploy.ai.remediation.RemediationContent> generateFindingRemediations(
            java.util.List<com.securedeploy.ai.remediation.RemediationContext> contexts,
            com.securedeploy.ai.remediation.RemediationPrompt prompt) {
        throw new UnsupportedOperationException("Finding remediation is not supported by this provider");
    }

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
