package com.securedeploy.ai.usage;

import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.dto.AiFeatureType;

public interface AiUsageTracker {

    AiUsageRecord track(AiFeatureType featureType, AiProviderType provider, String prompt,
                        String generatedContent, AiTokenUsage tokenUsage);
}
