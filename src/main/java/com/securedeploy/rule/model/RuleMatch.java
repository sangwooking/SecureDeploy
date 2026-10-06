package com.securedeploy.rule.model;

public record RuleMatch(
        String ruleId,
        RuleCategory category,
        Severity severity,
        String filePath,
        int line,
        String message,
        String recommendation,
        String evidence,
        FalsePositiveRisk falsePositiveRisk,
        DetectionConfidence confidence,
        String analysisNote
) {

    public RuleMatch(String ruleId, RuleCategory category, Severity severity, String filePath, int line,
                     String message, String recommendation, String evidence) {
        this(ruleId, category, severity, filePath, line, message, recommendation, evidence,
                FalsePositiveRisk.LOW, DetectionConfidence.HIGH, null);
    }

    public RuleMatch withFalsePositiveAnalysis(Severity adjustedSeverity, FalsePositiveRisk adjustedFalsePositiveRisk,
                                               DetectionConfidence adjustedConfidence, String adjustedAnalysisNote) {
        return new RuleMatch(
                ruleId,
                category,
                adjustedSeverity,
                filePath,
                line,
                message,
                recommendation,
                evidence,
                adjustedFalsePositiveRisk,
                adjustedConfidence,
                adjustedAnalysisNote
        );
    }
}
