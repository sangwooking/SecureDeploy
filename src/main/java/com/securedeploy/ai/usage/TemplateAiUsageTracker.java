package com.securedeploy.ai.usage;

import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.dto.AiFeatureType;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import org.springframework.stereotype.Component;

@Component
public class TemplateAiUsageTracker implements AiUsageTracker {

    private final AiProperties aiProperties;

    public TemplateAiUsageTracker(AiProperties aiProperties) {
        this.aiProperties = aiProperties;
    }

    @Override
    public AiUsageRecord track(AiFeatureType featureType, AiProviderType provider, String prompt,
                               String generatedContent, AiTokenUsage tokenUsage) {
        if (tokenUsage != null) {
            return new AiUsageRecord(
                    provider,
                    featureType,
                    tokenUsage.promptTokens(),
                    tokenUsage.completionTokens(),
                    tokenUsage.totalTokens(),
                    BigDecimal.ZERO,
                    tokenUsage.billable(),
                    LocalDateTime.now()
            );
        }

        if (!aiProperties.isUsageTrackingEnabled()) {
            return new AiUsageRecord(provider, featureType, 0, 0, 0, BigDecimal.ZERO, false, LocalDateTime.now());
        }

        int promptTokens = estimateTokens(prompt);
        int completionTokens = estimateTokens(generatedContent);
        return new AiUsageRecord(
                provider,
                featureType,
                promptTokens,
                completionTokens,
                promptTokens + completionTokens,
                BigDecimal.ZERO,
                false,
                LocalDateTime.now()
        );
    }

    private int estimateTokens(String text) {
        if (text == null || text.isBlank()) {
            return 0;
        }
        return Math.max(1, (int) Math.ceil(text.length() / 4.0));
    }
}
