package com.securedeploy.rule.rules;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DependencyRuleBeanRegistrationTest {

    @Autowired
    private List<VulnerabilityRule> rules;

    @Test
    void dependencyRulesAreRegisteredAsSpringBeans() {
        assertThat(rules)
                .extracting(rule -> rule.getClass().getSimpleName())
                .contains(
                        "VulnerableNpmDependencyRule",
                        "VulnerableMavenDependencyRule",
                        "VulnerableGradleDependencyRule",
                        "OutdatedDockerBaseImageRule"
                );
    }
}
