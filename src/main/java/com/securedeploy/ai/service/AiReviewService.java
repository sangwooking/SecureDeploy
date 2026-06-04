package com.securedeploy.ai.service;

import com.securedeploy.ai.context.AiCodeSnippet;
import com.securedeploy.auth.service.ReviewAccessService;
import com.securedeploy.ai.context.SnippetType;
import com.securedeploy.ai.dto.AiComparisonInsightResponse;
import com.securedeploy.ai.dto.AiFeatureType;
import com.securedeploy.ai.dto.AiPriorityItemResponse;
import com.securedeploy.ai.dto.AiPriorityResponse;
import com.securedeploy.ai.dto.AiProjectContext;
import com.securedeploy.ai.dto.AiProjectSummaryContent;
import com.securedeploy.ai.dto.AiProjectSummaryResponse;
import com.securedeploy.ai.dto.AiRemediationResponse;
import com.securedeploy.ai.dto.AiRemediationResultResponse;
import com.securedeploy.ai.dto.AiReviewRequest;
import com.securedeploy.ai.dto.AiReviewResponse;
import com.securedeploy.ai.dto.AiReviewResultResponse;
import com.securedeploy.ai.dto.AiRoadmapActionResponse;
import com.securedeploy.ai.dto.AiSecurityAuditFindingResponse;
import com.securedeploy.ai.dto.AiSecurityAuditResponse;
import com.securedeploy.ai.dto.AiSecurityRoadmapContent;
import com.securedeploy.ai.dto.AiSecurityRoadmapResponse;
import com.securedeploy.ai.dto.AiUsageResponse;
import com.securedeploy.ai.dto.AiVulnerabilityFinding;
import com.securedeploy.ai.prompt.PromptBuilder;
import com.securedeploy.ai.usage.AiTokenUsage;
import com.securedeploy.ai.usage.AiUsageRecord;
import com.securedeploy.ai.usage.AiUsageTracker;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.entity.ReviewSnippetEntity;
import com.securedeploy.persistence.entity.VulnerabilityEntity;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AiReviewService {

    private final ReviewRepository reviewRepository;
    private final ReviewAccessService reviewAccessService;
    private final PromptBuilder promptBuilder;
    private final AiProviderResolver aiProviderResolver;
    private final AiUsageTracker aiUsageTracker;

    public AiReviewService(ReviewRepository reviewRepository, ReviewAccessService reviewAccessService, PromptBuilder promptBuilder,
                           AiProviderResolver aiProviderResolver, AiUsageTracker aiUsageTracker) {
        this.reviewRepository = reviewRepository;
        this.reviewAccessService = reviewAccessService;
        this.promptBuilder = promptBuilder;
        this.aiProviderResolver = aiProviderResolver;
        this.aiUsageTracker = aiUsageTracker;
    }

    @Transactional(readOnly = true)
    public AiReviewResultResponse generateReview(Long reviewId) {
        ReviewEntity review = findReview(reviewId, "AI 리뷰를 생성할 분석 이력을 찾을 수 없습니다.");
        AiProjectContext context = toProjectContext(review);
        String usagePrompt = promptBuilder.buildVulnerabilityReviewBatchPrompt(context);

        GeneratedResult<List<AiReviewResponse>> generated = generateWithFallback(
                AiFeatureType.VULNERABILITY_REVIEW,
                usagePrompt,
                provider -> review.getVulnerabilities().stream()
                        .sorted(Comparator.comparingInt(vulnerability -> severityRank(vulnerability.getSeverity())))
                        .map(vulnerability -> generateForVulnerability(provider, vulnerability))
                        .toList()
        );

        return new AiReviewResultResponse(review.getId(), LocalDateTime.now(), generated.value(), generated.usage());
    }

    @Transactional(readOnly = true)
    public AiProjectSummaryResponse generateProjectSummary(Long reviewId) {
        ReviewEntity review = findReview(reviewId, "AI 종합 진단을 생성할 분석 이력을 찾을 수 없습니다.");
        AiProjectContext context = toProjectContext(review);
        String prompt = promptBuilder.buildProjectSummaryPrompt(context);

        GeneratedResult<AiProjectSummaryContent> generated = generateWithFallback(
                AiFeatureType.PROJECT_SUMMARY,
                prompt,
                provider -> provider.generateProjectSummary(context, prompt)
        );

        return AiProjectSummaryResponse.from(review.getId(), LocalDateTime.now(), generated.value(), generated.usage());
    }

    @Transactional(readOnly = true)
    public AiRemediationResultResponse generateRemediationSuggestions(Long reviewId) {
        ReviewEntity review = findReview(reviewId, "AI 수정 제안을 생성할 분석 이력을 찾을 수 없습니다.");
        AiProjectContext context = toProjectContext(review);
        String prompt = promptBuilder.buildRemediationPrompt(context);

        GeneratedResult<List<AiRemediationResponse>> generated = generateWithFallback(
                AiFeatureType.REMEDIATION_SUGGESTION,
                prompt,
                provider -> provider.generateRemediationSuggestions(context, prompt)
        );

        return new AiRemediationResultResponse(review.getId(), LocalDateTime.now(), generated.value(), generated.usage());
    }

    @Transactional(readOnly = true)
    public AiSecurityAuditResponse generateSecurityAudit(Long reviewId) {
        ReviewEntity review = findReview(reviewId, "AI 보조 진단을 생성할 분석 이력을 찾을 수 없습니다.");
        AiProjectContext context = toProjectContext(review);
        String prompt = promptBuilder.buildSecurityAuditPrompt(context);

        GeneratedResult<List<AiSecurityAuditFindingResponse>> generated = generateWithFallback(
                AiFeatureType.SECURITY_AUDIT,
                prompt,
                provider -> provider.generateSecurityAudit(context, prompt)
        );

        return new AiSecurityAuditResponse(review.getId(), LocalDateTime.now(), referencedFiles(context), generated.value(), generated.usage());
    }


    @Transactional(readOnly = true)
    public AiComparisonInsightResponse generateComparisonInsight(ReviewComparisonResponse comparison) {
        String prompt = promptBuilder.buildComparisonInsightPrompt(comparison);
        GeneratedResult<AiComparisonInsightResponse> generated = generateWithFallback(
                AiFeatureType.COMPARISON_INSIGHT,
                prompt,
                provider -> provider.generateComparisonInsight(comparison, prompt)
        );
        return generated.value().withUsage(generated.usage());
    }

    @Transactional(readOnly = true)
    public AiPriorityResponse generatePriorities(Long reviewId) {
        ReviewEntity review = findReview(reviewId, "AI 수정 우선순위를 생성할 분석 이력을 찾을 수 없습니다.");
        AiProjectContext context = toProjectContext(review);
        String prompt = promptBuilder.buildPriorityPrompt(context);
        GeneratedResult<List<AiPriorityItemResponse>> generated = generateWithFallback(
                AiFeatureType.PRIORITY_PLANNING,
                prompt,
                provider -> provider.generatePriorities(context, prompt)
        );
        return new AiPriorityResponse(review.getId(), LocalDateTime.now(), generated.value(), generated.usage());
    }

    @Transactional(readOnly = true)
    public AiSecurityRoadmapResponse generateSecurityRoadmap(Long reviewId) {
        ReviewEntity review = findReview(reviewId, "AI 보안 개선 로드맵을 생성할 분석 이력을 찾을 수 없습니다.");
        AiProjectContext context = toProjectContext(review);
        String prompt = promptBuilder.buildSecurityRoadmapPrompt(context);
        GeneratedResult<AiSecurityRoadmapContent> generated = generateWithFallback(
                AiFeatureType.SECURITY_ROADMAP,
                prompt,
                provider -> provider.generateSecurityRoadmap(context, prompt)
        );
        AiSecurityRoadmapContent roadmap = generated.value();
        return new AiSecurityRoadmapResponse(
                review.getId(),
                LocalDateTime.now(),
                roadmap.immediateActions(),
                roadmap.thisWeekActions(),
                roadmap.beforeDeploymentChecklist(),
                roadmap.longTermImprovements(),
                generated.usage()
        );
    }

    private <T> GeneratedResult<T> generateWithFallback(AiFeatureType featureType, String prompt, Function<AiProvider, T> generator) {
        AiProvider provider = aiProviderResolver.resolve();
        try {
            T value = generator.apply(provider);
            AiUsageResponse usage = trackUsage(featureType, provider, prompt, value);
            return new GeneratedResult<>(value, usage);
        } catch (RuntimeException openAiFailure) {
            AiProvider fallbackProvider = aiProviderResolver.templateProvider();
            if (provider == fallbackProvider) {
                throw openAiFailure;
            }
            T fallbackValue = generator.apply(fallbackProvider);
            AiUsageResponse usage = trackUsage(featureType, fallbackProvider, prompt, fallbackValue);
            return new GeneratedResult<>(fallbackValue, usage);
        }
    }

    private AiUsageResponse trackUsage(AiFeatureType featureType, AiProvider provider, String prompt, Object generatedContent) {
        Optional<AiTokenUsage> tokenUsage = provider.consumeLastTokenUsage();
        AiUsageRecord usage = aiUsageTracker.track(
                featureType,
                provider.providerType(),
                prompt,
                String.valueOf(generatedContent),
                tokenUsage.orElse(null)
        );
        return AiUsageResponse.from(usage);
    }

    private ReviewEntity findReview(Long reviewId, String notFoundMessage) {
        return reviewAccessService.findAccessibleReviewWithVulnerabilities(reviewId, notFoundMessage);
    }

    private AiReviewResponse generateForVulnerability(AiProvider provider, VulnerabilityEntity vulnerability) {
        AiReviewRequest request = new AiReviewRequest(
                vulnerability.getRuleId(),
                vulnerability.getSeverity(),
                vulnerability.getCategory(),
                vulnerability.getFilePath(),
                vulnerability.getLine(),
                vulnerability.getMessage(),
                vulnerability.getRecommendation(),
                vulnerability.getEvidence()
        );
        String prompt = promptBuilder.buildVulnerabilityReviewPrompt(request);
        return provider.generateVulnerabilityReview(request, prompt);
    }

    private AiProjectContext toProjectContext(ReviewEntity review) {
        List<AiVulnerabilityFinding> findings = review.getVulnerabilities().stream()
                .sorted(Comparator.comparingInt(vulnerability -> severityRank(vulnerability.getSeverity())))
                .map(AiVulnerabilityFinding::from)
                .toList();

        return new AiProjectContext(
                review.getId(),
                review.getProjectName(),
                review.getSourceType(),
                review.getRepositoryUrl(),
                review.getCreatedAt(),
                review.getScannedFileCount(),
                review.getVulnerabilityCount(),
                review.getSecurityScore(),
                review.getDeploymentStatus(),
                findings,
                snippetsByType(review, SnippetType.SECURITY_CONFIG),
                snippetsByType(review, SnippetType.CONTROLLER),
                snippetsByType(review, SnippetType.SERVICE),
                snippetsByType(review, SnippetType.REPOSITORY),
                snippetsByType(review, SnippetType.CONFIG),
                snippetsByType(review, SnippetType.CLIENT)
        );
    }

    private List<AiCodeSnippet> snippetsByType(ReviewEntity review, SnippetType type) {
        return review.getSnippets().stream()
                .filter(snippet -> snippet.getType() == type)
                .map(this::toSnippet)
                .toList();
    }

    private AiCodeSnippet toSnippet(ReviewSnippetEntity snippet) {
        return new AiCodeSnippet(snippet.getFilePath(), snippet.getContent());
    }

    private List<String> referencedFiles(AiProjectContext context) {
        return context.allSnippets().stream()
                .map(AiCodeSnippet::filePath)
                .distinct()
                .toList();
    }

    private int severityRank(com.securedeploy.rule.model.Severity severity) {
        return switch (severity) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
        };
    }

    private record GeneratedResult<T>(T value, AiUsageResponse usage) {
    }
}
