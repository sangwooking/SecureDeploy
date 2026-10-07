package com.securedeploy.risk.model;

import java.util.List;
import com.securedeploy.sca.model.DependencyVulnerability;

public record RiskFinding(
        String findingId, Source source, FindingCategory findingCategory,
        Long vulnerabilityId, String ruleId, String ecosystem, String packageName,
        String version, String advisoryId, List<String> sourceFiles,
        RiskPriority priority, String reasonCode, String priorityReason,
        DependencyFacts dependencyFacts,
        DependencyVulnerability dependency
) {
    public RiskFinding(String findingId, Source source, FindingCategory findingCategory, Long vulnerabilityId,
                       String ruleId, String ecosystem, String packageName, String version, String advisoryId,
                       List<String> sourceFiles, RiskPriority priority, String reasonCode, String priorityReason,
                       DependencyFacts dependencyFacts) {
        this(findingId, source, findingCategory, vulnerabilityId, ruleId, ecosystem, packageName, version, advisoryId,
                sourceFiles, priority, reasonCode, priorityReason, dependencyFacts, null);
    }
    public enum Source { CODE, DEPENDENCY, ANALYSIS }
    public record DependencyFacts(boolean exactVersion, boolean lookupConfirmed,
                                  Boolean direct, List<String> scopes, boolean fixedVersionAvailable,
                                  Double cvssScore) { }
}
