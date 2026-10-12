package com.securedeploy.ai.semantic;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.dto.*;
import com.securedeploy.ai.prompt.PromptBuilder;
import com.securedeploy.ai.service.AiProviderResolver;
import com.securedeploy.ai.usage.*;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.model.ScanMode;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import static com.securedeploy.ai.semantic.SemanticSnapshot.Status.*;

@Service
public class SemanticReviewService {
    private final AiProviderResolver resolver;
    private final AiProperties properties;
    private final SemanticProperties limits;
    private final PromptBuilder prompts;
    private final ObjectMapper mapper;
    private final SemanticOutputValidator validator;
    private final AiUsageTracker tracker;
    public SemanticReviewService(AiProviderResolver resolver, AiProperties properties, SemanticProperties limits,
                                 PromptBuilder prompts, ObjectMapper mapper, SemanticOutputValidator validator, AiUsageTracker tracker) {
        this.resolver=resolver; this.properties=properties; this.limits=limits; this.prompts=prompts;
        this.mapper=mapper; this.validator=validator; this.tracker=tracker;
    }
    public SemanticSnapshot generate(SecurityReviewResponse review, ScanMode mode, SecuritySliceCollector.Collection collection) {
        List<String> notices = new ArrayList<>(collection.limitations());
        notices.add("AI 보조 분석 후보이며 확정 취약점이 아닙니다. 기존 배포 판단과 취약점 수는 변경하지 않습니다.");
        if (mode == ScanMode.STANDARD) return empty(mode, NOT_REQUESTED, "Standard scan: no automatic external AI calls.", notices);
        if (!collection.available()) return empty(mode, UNAVAILABLE, "Java context unavailable.", notices);
        if (properties.getProvider()!=AiProviderType.OPENAI) return empty(mode, NOT_REQUESTED, "Template provider does not generate semantic candidates.", notices);
        var provider = resolver.resolve();
        if (provider.providerType()!=AiProviderType.OPENAI || limits.getMaxRequests()==0)
            return empty(mode, UNAVAILABLE, "External provider unavailable or request budget disabled.", notices);
        if (collection.slices().isEmpty()) return empty(mode, NO_SUPPORTED_CONTEXT, "No supported Java endpoint context; not a safety verdict.", notices);
        var slices = new ArrayList<>(collection.slices().stream().map(slice -> attachFindings(slice, review)).toList());
        SemanticPrompt prompt = null;
        int omitted = collection.omittedSlices();
        while (!slices.isEmpty() && prompt==null) {
            try { prompt = prompts.buildSemanticReviewPrompt(slices, mapper, limits); }
            catch (IllegalArgumentException budget) { slices.remove(slices.size()-1); omitted++; }
        }
        if (prompt==null) return empty(mode, UNAVAILABLE, "No slice fits the outbound context budget.", notices);
        provider.consumeLastTokenUsage();
        SemanticOutputValidator.Validated validated = new SemanticOutputValidator.Validated(List.of(),List.of(),0,0);
        SemanticSnapshot.Status status;
        AiUsageResponse usage;
        try {
            validated = validator.validate(provider.generateSemanticReview(List.copyOf(slices), prompt), slices, properties.getOpenai().getModel());
            status = validated.rejected()>0 ? validated.candidates().isEmpty() && validated.supporting().isEmpty() ? REJECTED : PARTIAL : COMPLETED;
        } catch (RuntimeException failure) {
            status = FAILED;
            notices.add("Semantic provider/output validation failed. No template candidates were invented.");
        } finally {
            usage = AiUsageResponse.from(tracker.track(AiFeatureType.SEMANTIC_REVIEW, AiProviderType.OPENAI, null, null,
                    provider.consumeLastTokenUsage().orElse(new AiTokenUsage(0,0,0,false))));
        }
        if (omitted>0) notices.add("Additional slices omitted by selection/context limits: " + omitted);
        return new SemanticSnapshot(1,UUID.randomUUID().toString(),mode,status,validated.candidates(),validated.supporting(),
                slices.stream().map(SecuritySlice::metadata).toList(),slices.size(),omitted,validated.rejected(),validated.duplicates(),
                status==FAILED ? "NOT_VALIDATED" : validated.rejected()>0 ? "REJECTED_ITEMS_REMOVED" : "LOCATION_VALIDATED_NOT_SECURITY_PROVEN",
                "openai",properties.getOpenai().getModel(),SemanticOutputValidator.PROMPT_VERSION,Instant.now(),1,usage,List.copyOf(notices));
    }
    private SecuritySlice attachFindings(SecuritySlice slice, SecurityReviewResponse review) {
        if (review.riskAssessment()==null) return slice;
        List<SecuritySlice.ExistingFinding> linked = new ArrayList<>();
        for (var finding : review.riskAssessment().codeFindings()) {
            review.vulnerabilities().stream().filter(v -> Objects.equals(v.vulnerabilityId(), finding.vulnerabilityId()))
                    .filter(v -> slice.contexts().stream().anyMatch(c -> c.filePath().equals(v.filePath()) && v.line()>=c.startLine() && v.line()<=c.endLine()))
                    .limit(20-linked.size()).forEach(v -> linked.add(new SecuritySlice.ExistingFinding(finding.findingId(),v.ruleId(),v.filePath(),v.line())));
            if (linked.size()>=20) break;
        }
        return slice.withFindings(linked);
    }
    public static SemanticSnapshot empty(ScanMode mode, SemanticSnapshot.Status status, String reason, List<String> notices) {
        var all = new ArrayList<>(notices); all.add(reason);
        return new SemanticSnapshot(1,UUID.randomUUID().toString(),mode,status,List.of(),List.of(),List.of(),0,0,0,0,"NOT_VALIDATED",
                "none",null,SemanticOutputValidator.PROMPT_VERSION,Instant.now(),0,null,List.copyOf(all));
    }
}
