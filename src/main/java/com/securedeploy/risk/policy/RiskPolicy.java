package com.securedeploy.risk.policy;

import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.model.RiskFinding.DependencyFacts;
import com.securedeploy.risk.model.RiskPriority;
import com.securedeploy.sca.model.DependencyVulnerability;

public interface RiskPolicy {
    String version();
    Decision code(VulnerabilityResultResponse finding);
    Decision dependency(DependencyVulnerability finding, DependencyFacts facts);
    record Decision(RiskPriority priority, RiskReason reason) { }
}
