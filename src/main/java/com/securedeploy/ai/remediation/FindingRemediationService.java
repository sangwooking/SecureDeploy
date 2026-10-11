package com.securedeploy.ai.remediation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.context.SnippetGroup;
import com.securedeploy.ai.dto.AiFeatureType;
import com.securedeploy.ai.dto.AiUsageResponse;
import com.securedeploy.ai.prompt.PromptBuilder;
import com.securedeploy.ai.service.AiProviderResolver;
import com.securedeploy.ai.usage.AiTokenUsage;
import com.securedeploy.ai.usage.AiUsageTracker;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.risk.model.FindingCategory;
import com.securedeploy.risk.model.RiskFinding;
import com.securedeploy.risk.model.RiskPriority;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import static com.securedeploy.ai.remediation.RemediationAdvice.GenerationStatus.*;

@Service
public class FindingRemediationService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(FindingRemediationService.class);
    public static final int MAX_ADVICE = 200;
    public static final int MAX_PAID_FINDINGS = 6;
    private static final Set<FindingCategory> SUPPORTED = Set.of(FindingCategory.CODE, FindingCategory.SECRET,
            FindingCategory.CONFIG, FindingCategory.DEPENDENCY);
    private final AiProviderResolver resolver;
    private final AiProperties properties;
    private final RemediationContextFactory contextFactory;
    private final RemediationSanitizer sanitizer;
    private final PromptBuilder prompts;
    private final ObjectMapper mapper;
    private final AiUsageTracker usageTracker;

    public FindingRemediationService(AiProviderResolver resolver, AiProperties properties,
                                     RemediationContextFactory contextFactory, RemediationSanitizer sanitizer,
                                     PromptBuilder prompts, ObjectMapper mapper, AiUsageTracker usageTracker) {
        this.resolver = resolver; this.properties = properties; this.contextFactory = contextFactory;
        this.sanitizer = sanitizer; this.prompts = prompts; this.mapper = mapper; this.usageTracker = usageTracker;
    }

    public RemediationSnapshot generate(SecurityReviewResponse review, SnippetGroup snippets) {
        if (review.riskAssessment() == null) return null;
        var findings = java.util.stream.Stream.concat(review.riskAssessment().codeFindings().stream(),
                review.riskAssessment().dependencyFindings().stream())
                .sorted(Comparator.comparing(RiskFinding::priority).thenComparing(RiskFinding::findingId)).toList();
        var selected = findings.stream().limit(MAX_ADVICE).toList();
        Map<String, RemediationContext> contexts = new LinkedHashMap<>();
        selected.stream().filter(f -> SUPPORTED.contains(f.findingCategory()))
                .forEach(f -> contexts.put(f.findingId(), contextFactory.create(f, review, snippets)));
        var contents = resolver.templateProvider().generateFindingRemediations(List.copyOf(contexts.values()), null);
        Map<String, RemediationContent> advice = new HashMap<>(contents);
        Set<String> generated = new HashSet<>();
        List<String> notices = new ArrayList<>();
        var provider = resolver.resolve();
        AiUsageResponse usage = null;
        var batch = new ArrayList<>(contexts.values().stream().filter(c -> c.priority() == RiskPriority.BLOCKING
                || c.priority() == RiskPriority.SHOULD_FIX).limit(MAX_PAID_FINDINGS).toList());
        if (properties.getProvider() == AiProviderType.OPENAI && provider.providerType() != AiProviderType.OPENAI)
            notices.add("OpenAI를 사용할 수 없어 template 가이드를 저장했습니다.");
        if (provider.providerType() == AiProviderType.OPENAI && !batch.isEmpty()) {
            RemediationPrompt prompt = null;
            while (!batch.isEmpty() && prompt == null) {
                try { prompt = prompts.buildFindingRemediationPrompt(batch, mapper); }
                catch (IllegalArgumentException budgetExceeded) { batch.remove(batch.size() - 1); }
            }
            if (prompt != null) {
                provider.consumeLastTokenUsage();
                try {
                    var output = provider.generateFindingRemediations(List.copyOf(batch), prompt);
                    if (output == null || output.size() != batch.size()) throw new IllegalArgumentException("Invalid remediation batch");
                    // Validate every item before accepting any output from this batch.
                    for (var context : batch) RemediationOutputValidator.validate(output.get(context.findingId()), context);
                    for (var context : batch) {
                        advice.put(context.findingId(), guard(context, output.get(context.findingId())));
                        generated.add(context.findingId());
                    }
                } catch (RuntimeException failure) {
                    // Never log provider bodies/prompts: an exception may contain credentials or source code.
                    String reason = failure instanceof RemediationValidationException validation
                            ? validation.reason().name() : "PROVIDER_OR_RESPONSE_FAILURE";
                    LOG.warn("Finding remediation fallback for review {}: {}", review.reviewId(), reason);
                    notices.add("AI 호출 또는 응답 검증 실패로 template 가이드를 저장했습니다. 기존 위험 평가는 변경되지 않았습니다.");
                } finally {
                    AiTokenUsage tokens = provider.consumeLastTokenUsage().orElse(new AiTokenUsage(0, 0, 0, false));
                    usage = AiUsageResponse.from(usageTracker.track(AiFeatureType.FINDING_REMEDIATION,
                            provider.providerType(), null, null, tokens));
                }
            }
            notices.add("유료 호출은 최대 6개 Finding, 1회 batch로 제한됩니다. 나머지는 template입니다.");
        }
        Instant now = Instant.now();
        List<RemediationAdvice> result = new ArrayList<>();
        for (var finding : selected) {
            var context = contexts.get(finding.findingId());
            boolean real = context != null && generated.contains(context.findingId());
            result.add(new RemediationAdvice(finding.findingId(), context == null ? null : sanitizer.output(advice.get(context.findingId())),
                    context == null ? "none" : real ? "openai" : "template", real ? properties.getOpenai().getModel() : null,
                    PromptBuilder.REMEDIATION_PROMPT_VERSION, now, context == null ? NOT_REQUESTED : real ? GENERATED : TEMPLATE));
        }
        return new RemediationSnapshot(1, UUID.randomUUID().toString(), now,
                contexts.isEmpty() ? NOT_REQUESTED : generated.isEmpty() ? TEMPLATE : GENERATED, List.copyOf(result),
                findings.size() - selected.size(), List.copyOf(notices), usage);
    }

    private RemediationContent guard(RemediationContext context, RemediationContent generated) {
        var baseline = RemediationTemplates.advice(context);
        if (context.dependency() != null) {
            // The executable upgrade guidance is always grounded in saved OSV versions, not model prose.
            return new RemediationContent(generated.summary(), generated.whyItMatters(), baseline.recommendedAction(),
                    null, null, baseline.verificationSteps(), baseline.caution(), generated.remediationConfidence());
        }
        if (context.findingCategory() == FindingCategory.SECRET) {
            return new RemediationContent(generated.summary(), generated.whyItMatters(), baseline.recommendedAction(),
                    generated.codeExample(), generated.configurationExample(), baseline.verificationSteps(),
                    baseline.caution(), generated.remediationConfidence());
        }
        return generated;
    }
}
