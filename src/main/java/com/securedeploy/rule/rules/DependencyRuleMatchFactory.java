package com.securedeploy.rule.rules;

import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.dependency.model.VulnerableDependencyInfo;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;

final class DependencyRuleMatchFactory {

    private DependencyRuleMatchFactory() {
    }

    static RuleMatch create(String ruleId, RuleCategory category, DependencyInfo dependency, VulnerableDependencyInfo vulnerability, String messagePrefix) {
        return new RuleMatch(
                ruleId,
                category,
                vulnerability.severity(),
                dependency.sourceFile(),
                dependency.line(),
                messagePrefix + " " + vulnerability.advisory(),
                vulnerability.recommendation(),
                evidence(dependency, vulnerability)
        );
    }

    private static String evidence(DependencyInfo dependency, VulnerableDependencyInfo vulnerability) {
        String safeVersion = vulnerability.safeVersion() == null || vulnerability.safeVersion().isBlank()
                ? "검토 필요"
                : vulnerability.safeVersion();
        return "dependency=" + dependency.name()
                + ", currentVersion=" + dependency.version()
                + ", safeVersion=" + safeVersion
                + ", ecosystem=" + dependency.ecosystem();
    }
}
