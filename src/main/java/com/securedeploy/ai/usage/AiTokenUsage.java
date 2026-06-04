package com.securedeploy.ai.usage;

public record AiTokenUsage(
        int promptTokens,
        int completionTokens,
        int totalTokens,
        boolean billable
) {
}
