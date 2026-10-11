package com.securedeploy.ai.remediation;

import com.securedeploy.risk.model.FindingCategory;
import com.securedeploy.risk.model.RiskPriority;
import java.util.List;

public record RemediationContext(String findingId, FindingCategory findingCategory, String ruleId,
                                 String severity, RiskPriority priority, String priorityReason,
                                 String confidence, String falsePositiveRisk, String filePath, Integer line,
                                 String maskedEvidence, String analysisNote, String untrustedCodeContext,
                                 DependencyContext dependency) {
    public record DependencyContext(String ecosystem, String packageName, String installedVersion,
                                    List<String> fixedVersions, List<String> advisoryIds, Double cvss,
                                    Boolean direct, List<String> scopes, String osvSummary,
                                    List<ThreatContext> threatIntelligence) { }
    public record ThreatContext(String cve, Double epss, Double percentile, Boolean knownExploited,
                                String epssStatus, String kevStatus) { }
}
