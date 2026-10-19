package com.securedeploy.analysis.deployment;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

/** Post-implementation synthetic variants, not an external or blind real-project benchmark. */
class DeploymentVariationTest {
    record Case(String body, String outcome) { }
    @Test void renamedServicesAndAlternateSyntaxPreserveRiskNormalAndUnknownDistinction() {
        var cases = List.of(
            new Case("cap_add: [CAP_NET_ADMIN]", "RISK"),
            new Case("security_opt: ['label=disable']", "RISK"),
            new Case("ports: ['[::]:9000:9000']", "RISK"),
            new Case("user: root:staff", "RISK"),
            new Case("cap_add: [NET_BIND_SERVICE]", "NORMAL"),
            new Case("volumes: ['/var/run/docker.sock']", "NORMAL"),
            new Case("ports: [{published: 8000, target: 80, host_ip: '127.0.0.1'}]", "NORMAL"),
            new Case("user: app:staff", "NORMAL"),
            new Case("privileged: '${PRIVILEGED}'", "UNKNOWN"),
            new Case("user: '${UID:-1000}'", "UNKNOWN"),
            new Case("volumes: ['${SOCKET}:/var/run/docker.sock']", "UNKNOWN"),
            new Case("ports: ['${PORT}:80']", "UNKNOWN")
        );
        var counts = new TreeMap<String, Integer>();
        for (int i = 0; i < cases.size(); i++) {
            var item = cases.get(i);
            var input = DeploymentAnalyzerTest.file("infra/compose.yaml", "services:\n  gateway_" + i + ":\n    user: '2000'\n    " + item.body());
            // Avoid intentionally invalid duplicate keys in cases that exercise user declarations.
            if (item.body().startsWith("user:")) input = DeploymentAnalyzerTest.file("infra/compose.yaml", "services:\n  gateway_" + i + ":\n    " + item.body());
            var result = DeploymentAnalyzerTest.inspect(input);
            assertThat(result.files().get(0).status()).as("variant %s", i).isEqualTo("PARSED");
            String actual = !result.findings().isEmpty() ? "RISK" : result.files().get(0).observations().stream().anyMatch(o -> o.valueStatus().equals("UNKNOWN")) ? "UNKNOWN" : "NORMAL";
            assertThat(actual).as("variant %s", i).isEqualTo(item.outcome());
            counts.merge(actual, 1, Integer::sum);
        }
        System.out.println("Configuration synthetic variants (not deployment safety accuracy): " + counts + "; FP=0 FN=0 within labeled supported cases");
    }
    @Test void configBudgetsPreserveOmittedEvidenceAndNeverReturnCleanStatus() {
        var files = new ArrayList<com.securedeploy.project.model.ProjectFile>();
        for (int i = 0; i < 55; i++) files.add(DeploymentAnalyzerTest.file("module" + i + "/compose.yml", "services: {web: {user: '1000'}}"));
        var result = DeploymentAnalyzerTest.inspect(files.toArray(com.securedeploy.project.model.ProjectFile[]::new));
        assertThat(result.status()).isEqualTo("PARTIAL");
        assertThat(result.files()).hasSize(55);
        assertThat(result.files()).filteredOn(f -> f.status().equals("LIMIT_EXCEEDED")).hasSize(5);
        StringBuilder huge = new StringBuilder("services:\n  a:\n    ports:\n");
        for (int i = 0; i < 220; i++) huge.append("      - '127.0.0.1:8000:80'\n");
        assertThat(DeploymentAnalyzerTest.inspect(DeploymentAnalyzerTest.file("compose.yml", huge.toString())).files().get(0).status()).isEqualTo("LIMIT_EXCEEDED");
        assertThat(DeploymentAnalyzerTest.inspect(DeploymentAnalyzerTest.file("wrangler.json", "[".repeat(40) + "]".repeat(40))).files().get(0).status()).isEqualTo("PARSE_FAILED");
        assertThat(DeploymentAnalyzerTest.inspect(DeploymentAnalyzerTest.file("wrangler.toml", "[" + "a.".repeat(100) + "b]\nx=1")).files().get(0).status()).isEqualTo("LIMIT_EXCEEDED");
    }
}
