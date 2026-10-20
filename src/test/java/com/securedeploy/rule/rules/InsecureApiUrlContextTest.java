package com.securedeploy.rule.rules;

import com.securedeploy.analysis.typescript.TypeScriptAnalysisProperties;
import com.securedeploy.project.model.*;
import com.securedeploy.rule.engine.*;
import com.securedeploy.rule.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class InsecureApiUrlContextTest {
    private List<RuleMatch> analyze(String code) { return analyze(code,new TypeScriptAnalysisProperties()); }
    private List<RuleMatch> analyze(String code,TypeScriptAnalysisProperties properties) {
        var file=new ProjectFile(Path.of("server.ts"),"server.ts",ProjectFileType.TYPESCRIPT,code.lines().toList());
        var project=new ProjectStructure(Path.of("."),List.of(file));
        return new VulnerabilityRuleEngine(List.of(new InsecureApiUrlRule()),new InsecureApiUrlContext(properties))
                .execute(new RuleExecutionContext(project));
    }
    @Test void originalPatternReproducesFalseWarningsButReconciliationNeedsProof() {
        String code="/** http://docs.example */\nconst p = new URL(input, 'http://base.example');\nuse(p.pathname);";
        var file=new ProjectFile(Path.of("server.ts"),"server.ts",ProjectFileType.TYPESCRIPT,code.lines().toList());
        assertThat(new InsecureApiUrlRule().evaluate(file)).hasSize(2);
        assertThat(analyze(code)).isEmpty();
    }
    @Test void httpRequestsAndUnknownServerAddressRemain() {
        var matches=analyze("fetch('http://remote.example/path');\nconst address = `http://${host}:${port}`;");
        assertThat(matches).hasSize(2);
        assertThat(matches.get(0).confidence()).isEqualTo(DetectionConfidence.HIGH);
        assertThat(matches.get(1).confidence()).isEqualTo(DetectionConfidence.LOW);
        assertThat(matches.get(1).analysisNote()).contains("확인하지 못했습니다");
    }
    @Test void parserFailureUnavailableDisabledOrLimitsRetainWarnings() {
        var disabled=new TypeScriptAnalysisProperties();disabled.setEnabled(false);
        assertThat(analyze("// http://docs.example",disabled)).hasSize(1);
        var missing=new TypeScriptAnalysisProperties();missing.setNodeExecutable("/no/such/trusted-node");
        assertThat(analyze("// http://docs.example",missing)).hasSize(1);
        assertThat(analyze("const = 'http://remote.example';")).hasSize(1);
        assertThat(analyze("/*"+"x".repeat(100001)+" http://docs.example */")).hasSize(1);
    }
    @Test void localhostLookalikeDomainsAreNotLocalhost() {
        assertThat(analyze("fetch('http://localhost:3000/api');")).isEmpty();
        assertThat(analyze("fetch('http://localhost.evil.example/api');")).hasSize(1);
        assertThat(analyze("fetch('http://127.0.0.1.evil.example/api');")).hasSize(1);
        assertThat(analyze("const local='http://localhost'; fetch('http://remote.example');")).hasSize(1);
    }
    @Test void parsingObjectSentToNetworkOrUnknownCallerIsNotExcluded() {
        for(String usage:List.of("fetch(p)","fetch(p.href)","return p", "wrapper(p)","p.pathname=input")) {
            assertThat(analyze("function f(input) { const p = new URL(input,'http://remote.example'); "+usage+"; }")).hasSize(1);
        }
    }
    @Test void largeDeclarationOnlySuppressesProvenLeadingCommentNotLaterCode() {
        assertThat(analyze("/** License http://license.example */\n"+"declare const value: string;\n".repeat(5000))).isEmpty();
        assertThat(analyze("/** License http://license.example */ fetch('http://remote.example');\n"+"declare const value: string;\n".repeat(5000))).hasSize(1);
    }
    @Test void uiTextCannotBecomeCredentialButActualAssignmentsRemain() {
        var file=new ProjectFile(Path.of("controls.ts"),"controls.ts",ProjectFileType.TYPESCRIPT,List.of(
                "button.innerText = hidden ? 'Show Secret' : 'Hide Secret';",
                "const secret = 'synthetic-secret-for-regression';"));
        var project=new ProjectStructure(Path.of("."),List.of(file));
        assertThat(new HardcodedFrontendSecretRule().evaluate(file)).hasSize(2);
        var matches=new VulnerabilityRuleEngine(List.of(new HardcodedFrontendSecretRule())).execute(new RuleExecutionContext(project));
        assertThat(matches).hasSize(1);assertThat(matches.get(0).line()).isEqualTo(2);
    }
}
