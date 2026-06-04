package com.securedeploy.rule.rules;

import com.securedeploy.dependency.advisory.VulnerableDependencyCatalog;
import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.dependency.parser.NpmLockDependencyParser;
import com.securedeploy.dependency.parser.PackageJsonDependencyParser;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class VulnerableNpmDependencyRule implements VulnerabilityRule {

    private final PackageJsonDependencyParser packageJsonParser = new PackageJsonDependencyParser();
    private final NpmLockDependencyParser lockDependencyParser = new NpmLockDependencyParser();
    private final VulnerableDependencyCatalog catalog = new VulnerableDependencyCatalog();

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isPackageJson(file) && !RuleFileTypes.isLockFile(file)) {
            return List.of();
        }
        List<DependencyInfo> dependencies = RuleFileTypes.isPackageJson(file)
                ? packageJsonParser.parse(file)
                : lockDependencyParser.parse(file);

        return dependencies.stream()
                .flatMap(dependency -> catalog.findVulnerability(dependency)
                        .map(vulnerability -> DependencyRuleMatchFactory.create(
                                "VULNERABLE_NPM_DEPENDENCY",
                                RuleCategory.DEPENDENCY,
                                dependency,
                                vulnerability,
                                dependency.name() + " " + dependency.version() + "은 알려진 취약 버전 후보입니다."
                        ))
                        .stream())
                .toList();
    }
}
