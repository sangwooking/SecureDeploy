package com.securedeploy.ai.dto;

import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.usage.AiUsageRecord;
import java.math.BigDecimal;
import java.time.LocalDateTime;

public record AiUsageResponse(
        AiProviderType provider,
        AiFeatureType featureType,
        int promptTokens,
        int completionTokens,
        int totalTokens,
        BigDecimal estimatedCostUsd,
        boolean billable,
        LocalDateTime trackedAt
) {

    public static AiUsageResponse from(AiUsageRecord record) {
        return new AiUsageResponse(
                record.provider(),
                record.featureType(),
                record.promptTokens(),
                record.completionTokens(),
                record.totalTokens(),
                record.estimatedCostUsd(),
                record.billable(),
                record.trackedAt()
        );
    }
}
