package com.securedeploy.ai.dto;

import java.util.List;

public record AiProjectSummaryContent(
        String overallSecurityStatus,
        String mostRiskyArea,
        List<String> priorityFixes,
        List<String> preDeploymentActions,
        String deploymentOpinion
) {
}
