package com.securedeploy.analysis.deployment;

import com.securedeploy.rule.rules.*;
import com.securedeploy.analysis.typescript.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static com.securedeploy.analysis.deployment.DeploymentAnalyzerTest.*;

class Supply29BoundaryTest {
    @Test void envKeysNotTheirValuesDriveCredentialDeclarationsAndNeverExposeValues() throws Exception {
        var input=file("Dockerfile","FROM alpine\nENV NOTE=\"SECRET=not-a-credential\" PASSWORD=\"\"\n");
        assertThat(new DockerSecretEnvRule().evaluate(input)).isEmpty();
        var secret=file("Dockerfile","FROM alpine\nENV PASSWORD=offline-fixture-only OTHER=public\n");
        var result=inspect(secret);assertThat(new DockerSecretEnvRule().evaluate(secret)).hasSize(1);
        assertThat(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(result)).doesNotContain("offline-fixture-only");
        assertThat(new DockerSecretEnvRule().evaluate(secret).get(0).evidence()).doesNotContain("offline-fixture-only");
        var converter=new ServerAnalysisConverter();var snapshot=ServerAnalysisSnapshot.unavailable("NOT_APPLICABLE",List.of(),"NO_TS").withDeploymentAnalysis(result);
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(snapshot))).isEqualTo(snapshot);
    }
    @Test void bothEnvSyntaxesQuotesContinuationsAndBudgetsAreBounded() {
        for(String declaration:List.of("ENV PASSWORD ''","ENV PASSWORD=\"\"","ENV PORT=8080 \\\n PASSWORD=''"))assertThat(new DockerSecretEnvRule().evaluate(file("Dockerfile","FROM alpine\n"+declaration))).isEmpty();
        var input=file("Dockerfile","FROM alpine\nENV "+"SECRET_1=value ".repeat(1000));
        assertThat(DockerEnvironment.inspect(input).complete()).isFalse();
        assertThat(inspect(input).files().get(0).observations()).hasSizeLessThanOrEqualTo(200);
        assertThat(inspect(file("Dockerfile","x".repeat(100001))).files().get(0).status()).isEqualTo("LIMIT_EXCEEDED");
    }
    @Test void weakEnvNameEvidenceCannotBecomeAConfirmedSecretBlock() {
        var f=file("Dockerfile","FROM alpine\nENV \\\n PASSWORD=offline-fixture-only\n");
        var p=new com.securedeploy.project.model.ProjectStructure(java.nio.file.Path.of("/unopened"),List.of(f));
        var filtered=new com.securedeploy.rule.filter.FalsePositiveAnalyzer().analyze(p,new DockerSecretEnvRule().evaluate(f));
        assertThat(filtered).hasSize(1);assertThat(filtered.get(0).line()).isEqualTo(3);
        var decision=new com.securedeploy.risk.policy.DefaultRiskPolicy().code(com.securedeploy.review.dto.VulnerabilityResultResponse.from(filtered.get(0)));
        assertThat(decision.priority().name()).isEqualTo("REVIEW_REQUIRED");
    }
    @Test void jobPermissionsOverrideAndCheckoutResetCannotInventPrivilege() {
        String head=Supply29ControlsTest.HEAD;
        for(String source:List.of(
            Supply29ControlsTest.workflow("pull_request_target","write-all",head+"      - run: npm ci\n").replace("runs-on: ubuntu-latest","permissions: {}\n    runs-on: ubuntu-latest"),
            Supply29ControlsTest.workflow("pull_request_target","write-all",head+"      - uses: actions/checkout@v4\n      - run: npm ci\n"),
            Supply29ControlsTest.workflow("pull_request_target","write-all",head.replace("        with:","        with:\n          persist-credentials: false")+"      - run: npm ci\n"),
            Supply29ControlsTest.workflow("pull_request_target","write-all",head+"      - run: |\n          exit 0\n          npm ci\n"))) {
            assertThat(inspect(file(".github/workflows/check.yml",source)).findings()).isEmpty();
        }
    }
    @Test void unsupportedYamlAndDynamicStepsNeverBecomeNegativeSecurityProof() {
        for(String source:List.of("on: push\njobs: &loop {x: *loop}","on: push\njobs: {}\njobs: {}","!!java.lang.ProcessBuilder {}")) {
            var r=inspect(file(".github/workflows/check.yml",source));assertThat(r.files().get(0).status()).isEqualTo("PARSE_FAILED");assertThat(r.findings()).isEmpty();
        }
        var source=Supply29ControlsTest.workflow("pull_request","{}","      - if: ${{ external.condition }}\n        run: echo '${{ github.event.pull_request.title }}'\n");
        var r=inspect(file(".github/workflows/check.yml",source));assertThat(r.findings()).isEmpty();
        assertThat(r.files().get(0).observations()).anyMatch(o->o.valueStatus().equals("UNKNOWN"));
    }
    @Test void envAndStepNamesAreNotShellProgramsButParseFailuresRetainLegacyWarnings() {
        var normal=file(".github/workflows/check.yml",Supply29ControlsTest.workflow("push","{}","      - name: echo secret\n        env: {ECHO: '${{ secrets.DEPLOY }}'}\n        run: echo normal\n"));
        assertThat(new GitHubActionsSecurityRule().evaluate(normal)).isEmpty();
        var risky=file(".github/workflows/check.yml",Supply29ControlsTest.workflow("push","{}","      - run: |\n          echo '${{ secrets.DEPLOY }}'\n"));
        assertThat(new GitHubActionsSecurityRule().evaluate(risky)).extracting(m->m.ruleId()).contains("GITHUB_ACTIONS_SECRET_ECHO");
        var invalid=file(".github/workflows/check.yml","jobs: [\n # echo ${{ secrets.DEPLOY }}\n");
        assertThat(new GitHubActionsSecurityRule().evaluate(invalid)).isNotEmpty();
    }
}
