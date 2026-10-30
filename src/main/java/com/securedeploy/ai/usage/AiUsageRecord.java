package com.securedeploy.ai.usage;

import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.dto.AiFeatureType;
import java.math.BigDecimal;
import java.time.LocalDateTime;

public record AiUsageRecord(
        AiProviderType provider,
        AiFeatureType featureType,
        int promptTokens,
        int completionTokens,
        int totalTokens,
        BigDecimal estimatedCostUsd,
        boolean billable,
        LocalDateTime trackedAt,
        String model, int cachedInputTokens, boolean usageKnown, String costStatus
) {
    public AiUsageRecord(AiProviderType provider,AiFeatureType featureType,int promptTokens,int completionTokens,int totalTokens,BigDecimal estimatedCostUsd,boolean billable,LocalDateTime trackedAt){this(provider,featureType,promptTokens,completionTokens,totalTokens,estimatedCostUsd,billable,trackedAt,null,0,false,estimatedCostUsd==null?"UNKNOWN":"LEGACY_ESTIMATE");}
}
