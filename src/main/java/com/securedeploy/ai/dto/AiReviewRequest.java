package com.securedeploy.ai.dto;

import com.securedeploy.rule.model.DetectionConfidence;
import com.securedeploy.rule.model.FalsePositiveRisk;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;

public record AiReviewRequest(
        String ruleId,
        Severity severity,
        RuleCategory category,
        String filePath,
        int line,
        String message,
        String recommendation,
        String evidence,
        FalsePositiveRisk falsePositiveRisk,
        DetectionConfidence confidence,
        String analysisNote
) {
}
