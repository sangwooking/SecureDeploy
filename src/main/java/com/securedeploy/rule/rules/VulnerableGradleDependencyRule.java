package com.securedeploy.rule.rules;

import com.securedeploy.dependency.advisory.VulnerableDependencyCatalog;
import com.securedeploy.dependency.parser.GradleDependencyParser;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class VulnerableGradleDependencyRule implements VulnerabilityRule {

    private final GradleDependencyParser parser = new GradleDependencyParser();
    private final VulnerableDependencyCatalog catalog = new VulnerableDependencyCatalog();

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isGradleBuild(file)) {
            return List.of();
        }
        return parser.parse(file).stream()
                .flatMap(dependency -> catalog.findVulnerability(dependency)
                        .map(vulnerability -> DependencyRuleMatchFactory.create(
                                "VULNERABLE_GRADLE_DEPENDENCY",
                                RuleCategory.DEPENDENCY,
                                dependency,
                                vulnerability,
                                dependency.name() + " " + dependency.version() + "은 알려진 취약 버전 후보입니다."
                        ))
                        .stream())
                .toList();
    }
}
