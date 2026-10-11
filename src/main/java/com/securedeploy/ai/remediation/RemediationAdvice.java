package com.securedeploy.ai.remediation;

import java.time.Instant;

public record RemediationAdvice(String findingId, RemediationContent advice, String provider, String model,
                                String promptVersion, Instant generatedAt, GenerationStatus generationStatus) {
    public enum GenerationStatus { GENERATED, TEMPLATE, UNAVAILABLE, FAILED, NOT_REQUESTED }
}
