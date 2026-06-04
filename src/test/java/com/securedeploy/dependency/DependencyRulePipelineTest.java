package com.securedeploy.dependency;

import static org.assertj.core.api.Assertions.assertThat;

import com.securedeploy.project.model.ProjectFileType;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.project.service.ProjectScanner;
import com.securedeploy.rule.engine.RuleExecutionContext;
import com.securedeploy.rule.engine.VulnerabilityRuleEngine;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.rules.OutdatedDockerBaseImageRule;
import com.securedeploy.rule.rules.VulnerableGradleDependencyRule;
import com.securedeploy.rule.rules.VulnerableMavenDependencyRule;
import com.securedeploy.rule.rules.VulnerableNpmDependencyRule;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class DependencyRulePipelineTest {

    @Test
    void sampleDependencyProjectIsCollectedAndDetected() {
        ProjectScanner scanner = new ProjectScanner(new ProjectFileCollector());
        ProjectStructure structure = scanner.scan(Path.of("sample-dependency-vulnerable"));

        assertThat(structure.analysisFiles())
                .extracting(file -> file.type())
                .contains(
                        ProjectFileType.PACKAGE_JSON,
                        ProjectFileType.LOCK_FILE,
                        ProjectFileType.XML,
                        ProjectFileType.GRADLE_BUILD,
                        ProjectFileType.DOCKERFILE
                );

        VulnerabilityRuleEngine engine = new VulnerabilityRuleEngine(List.of(
                new VulnerableNpmDependencyRule(),
                new VulnerableMavenDependencyRule(),
                new VulnerableGradleDependencyRule(),
                new OutdatedDockerBaseImageRule()
        ));
        List<RuleMatch> matches = engine.execute(new RuleExecutionContext(structure));

        assertThat(matches).extracting(RuleMatch::ruleId).contains(
                "VULNERABLE_NPM_DEPENDENCY",
                "VULNERABLE_MAVEN_DEPENDENCY",
                "VULNERABLE_GRADLE_DEPENDENCY",
                "OUTDATED_DOCKER_BASE_IMAGE"
        );
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=lodash") && evidence.contains("currentVersion=4.17.10"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=minimist") && evidence.contains("currentVersion=1.2.0"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=axios") && evidence.contains("currentVersion=0.20.0"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=serialize-javascript") && evidence.contains("currentVersion=2.1.2"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=org.apache.logging.log4j:log4j-core") && evidence.contains("currentVersion=2.14.1"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=com.fasterxml.jackson.core:jackson-databind") && evidence.contains("currentVersion=2.9.10"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=org.springframework:spring-webmvc") && evidence.contains("currentVersion=5.3.10"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=commons-collections:commons-collections") && evidence.contains("currentVersion=3.2.1"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=ubuntu") && evidence.contains("currentVersion=18.04"));
        assertThat(matches).extracting(RuleMatch::evidence).anyMatch(evidence -> evidence.contains("dependency=node") && evidence.contains("currentVersion=latest"));
    }
}
