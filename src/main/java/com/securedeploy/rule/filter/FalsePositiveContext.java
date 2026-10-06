package com.securedeploy.rule.filter;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleMatch;

record FalsePositiveContext(
        RuleMatch match,
        ProjectFile file,
        String sourceLine
) {
}
