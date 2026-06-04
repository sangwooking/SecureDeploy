package com.securedeploy.ai.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "securedeploy.ai")
public class AiProperties {

    private AiProviderType provider = AiProviderType.TEMPLATE;
    private boolean usageTrackingEnabled = true;
    private final OpenAi openai = new OpenAi();

    public AiProviderType getProvider() {
        return provider;
    }

    public void setProvider(AiProviderType provider) {
        this.provider = provider;
    }

    public boolean isUsageTrackingEnabled() {
        return usageTrackingEnabled;
    }

    public void setUsageTrackingEnabled(boolean usageTrackingEnabled) {
        this.usageTrackingEnabled = usageTrackingEnabled;
    }

    public OpenAi getOpenai() {
        return openai;
    }

    public static class OpenAi {

        private String apiKey = "";
        private String model = "gpt-5.4-mini";
        private int timeoutSeconds = 30;

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getModel() {
            return model;
        }

        public void setModel(String model) {
            this.model = model;
        }

        public int getTimeoutSeconds() {
            return timeoutSeconds;
        }

        public void setTimeoutSeconds(int timeoutSeconds) {
            this.timeoutSeconds = timeoutSeconds;
        }
    }
}
