package com.securedeploy.risk.policy;

import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.model.RiskFinding.DependencyFacts;
import com.securedeploy.risk.model.RiskPriority;
import com.securedeploy.sca.model.DependencyVulnerability;
import com.securedeploy.threatintel.model.ThreatIntelligence;
import java.util.List;

public interface RiskPolicy {
    String version();
    Decision code(VulnerabilityResultResponse finding);
    Decision dependency(DependencyVulnerability finding, DependencyFacts facts);
    Decision dependency(DependencyVulnerability finding, DependencyFacts facts, List<ThreatIntelligence> intelligence);
    boolean requiresThreatReview(DependencyVulnerability finding, DependencyFacts facts, List<ThreatIntelligence> intelligence);
    ThreatRiskThresholds threatThresholds();
    record Decision(RiskPriority priority, RiskReason reason) { }
}
