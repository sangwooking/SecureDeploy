package com.securedeploy.rule.engine;

import com.securedeploy.project.model.ProjectStructure;

public record RuleExecutionContext(
        ProjectStructure projectStructure
) {
}
