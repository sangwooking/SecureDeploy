package com.securedeploy.rule.rules;

import com.securedeploy.dependency.advisory.VulnerableDependencyCatalog;
import com.securedeploy.dependency.parser.DockerImageDependencyParser;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class OutdatedDockerBaseImageRule implements VulnerabilityRule {

    private final DockerImageDependencyParser parser = new DockerImageDependencyParser();
    private final VulnerableDependencyCatalog catalog = new VulnerableDependencyCatalog();

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isDockerfile(file) && !RuleFileTypes.isDockerCompose(file)) {
            return List.of();
        }
        return parser.parse(file).stream()
                .flatMap(dependency -> catalog.findVulnerability(dependency)
                        .map(vulnerability -> DependencyRuleMatchFactory.create(
                                "OUTDATED_DOCKER_BASE_IMAGE",
                                RuleCategory.CONTAINER_SECURITY,
                                dependency,
                                vulnerability,
                                dependency.name() + ":" + dependency.version() + " 이미지는 업데이트가 필요한 base image 후보입니다."
                        ))
                        .stream())
                .toList();
    }
}
