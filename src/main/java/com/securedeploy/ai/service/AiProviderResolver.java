package com.securedeploy.ai.service;

import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.ai.config.AiProviderType;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class AiProviderResolver {

    private final AiProperties aiProperties;
    private final Map<AiProviderType, AiProvider> providers = new EnumMap<>(AiProviderType.class);

    public AiProviderResolver(AiProperties aiProperties, List<AiProvider> providers) {
        this.aiProperties = aiProperties;
        providers.forEach(provider -> this.providers.put(provider.providerType(), provider));
    }

    public AiProvider resolve() {
        AiProvider provider = providers.get(aiProperties.getProvider());
        if (provider != null && provider.isAvailable()) {
            return provider;
        }
        return templateProvider();
    }

    public AiProvider templateProvider() {
        AiProvider templateProvider = providers.get(AiProviderType.TEMPLATE);
        if (templateProvider == null) {
            throw new IllegalStateException("Template AI Provider가 등록되어 있지 않습니다.");
        }
        return templateProvider;
    }
}
