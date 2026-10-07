package com.securedeploy.risk.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record RiskAssessment(
        int schemaVersion, String policyVersion, Instant assessedAt,
        String assessmentScope, DeploymentAssessment prioritizedDeploymentAssessment,
        String assessmentReason, Coverage assessmentCoverage,
        Map<RiskPriority, Long> prioritySummary,
        Map<RiskFinding.Source, Map<RiskPriority, Long>> prioritySummaryBySource,
        List<RiskFinding> codeFindings, List<RiskFinding> dependencyFindings,
        List<RiskFinding> reviewRequirements,
        List<DependencyCorrelation> dependencyCorrelations
) {
    public enum Completion { COMPLETE, PARTIAL, FAILED, NOT_INCLUDED, UNKNOWN }
    public record Coverage(Completion overall, Completion ruleEngine, Completion sca,
                           Completion ai, String scopeNote) { }
}
