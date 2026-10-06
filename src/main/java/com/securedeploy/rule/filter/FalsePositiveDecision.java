package com.securedeploy.rule.filter;

import com.securedeploy.rule.model.DetectionConfidence;
import com.securedeploy.rule.model.FalsePositiveRisk;
import com.securedeploy.rule.model.Severity;

record FalsePositiveDecision(
        FalsePositiveAction action,
        Severity severity,
        FalsePositiveRisk falsePositiveRisk,
        DetectionConfidence confidence,
        String analysisNote
) {

    static FalsePositiveDecision keep(Severity severity, FalsePositiveRisk risk, DetectionConfidence confidence, String note) {
        return new FalsePositiveDecision(FalsePositiveAction.KEEP, severity, risk, confidence, note);
    }

    static FalsePositiveDecision exclude(String note) {
        return new FalsePositiveDecision(FalsePositiveAction.EXCLUDE, null, FalsePositiveRisk.HIGH, DetectionConfidence.LOW, note);
    }
}
