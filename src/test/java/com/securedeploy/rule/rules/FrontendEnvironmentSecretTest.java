package com.securedeploy.rule.rules;

import com.securedeploy.project.model.*;
import com.securedeploy.rule.filter.FalsePositiveAnalyzer;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class FrontendEnvironmentSecretTest {
    @Test void supabasePublishableFormatIsNotSecretButSecretFormatIsRetainedAndMasked() {
        String publicKey="sb_publishable_"+"Ab2Cd3Ef4Gh5Jk6Lm7Np8Qr9St0Uv1Wx";
        String secretKey="sb_secret_"+"A".repeat(32);
        assertThat(rule.evaluate(file("VITE_API_KEY="+publicKey))).isEmpty();
        assertThat(rule.evaluate(file("NEXT_PUBLIC_API_KEY="+publicKey))).isEmpty();
        var source=file("NEXT_PUBLIC_API_KEY="+secretKey);var raw=rule.evaluate(source);
        assertThat(raw).hasSize(1).allSatisfy(m->assertThat(m.evidence()).doesNotContain(secretKey).contains("redacted"));
        var finalMatches=new FalsePositiveAnalyzer().analyze(new ProjectStructure(Path.of("."),List.of(source)),raw);
        assertThat(finalMatches).hasSize(1).allSatisfy(m->assertThat(m.confidence().name()).isEqualTo("HIGH"));
        assertThat(new com.securedeploy.ai.remediation.RemediationSanitizer().text("diagnostic: "+secretKey,1000))
                .doesNotContain(secretKey).contains("redacted");
    }
    final HardcodedFrontendSecretRule rule=new HardcodedFrontendSecretRule();
    final String fake="ghp_"+"a".repeat(36);
    ProjectFile file(String line) { return new ProjectFile(Path.of(".env"),".env",ProjectFileType.ENV_FILE,List.of(line)); }
    @Test void realBoundaryAndWhitespaceRecognizeSyntheticCredentialExactlyOnce() {
        for(String line:List.of("VITE_API_KEY="+fake,"\texport NEXT_PUBLIC_API_KEY = '"+fake+"' # fixture","VITE_API_KEY\t=\t\""+fake+"\"")) {
            var matches=rule.evaluate(file(line));assertThat(matches).hasSize(1);
            assertThat(matches.get(0).evidence()).doesNotContain(fake).contains("redacted");
        }
    }
    @Test void publicConfigurationIdentifiersAndExternalReferencesAreNotSecretsByName() {
        for(String line:List.of("VITE_API_KEY=public-client-id","NEXT_PUBLIC_API_KEY=https://api.example.invalid","VITE_TOKEN=550e8400-e29b-41d4-a716-446655440000","VITE_API_KEY=${PUBLIC_API_KEY}","VITE_API_KEY=pk_live_public_identifier","VITE_API_BASE_URL=https://service.invalid"))
            assertThat(rule.evaluate(file(line))).as(line).isEmpty();
    }
    @Test void commentsPartialNamesAndShellSyntaxDoNotTurnIntoEnvDeclarations() {
        for(String line:List.of("# VITE_API_KEY="+fake,"console.log('VITE_API_KEY="+fake+"')","OTHER VITE_API_KEY="+fake))assertThat(rule.evaluate(file(line))).isEmpty();
    }
    @Test void dummyValuesRemainExcludedAndFalsePositiveProcessingRetainsStrongPattern() {
        assertThat(rule.evaluate(file("VITE_SECRET=changeme"))).isEmpty();
        var f=file("VITE_API_KEY="+fake);var matches=rule.evaluate(f);
        assertThat(new FalsePositiveAnalyzer().analyze(new ProjectStructure(Path.of("."),List.of(f)),matches)).hasSize(1);
    }
    @Test void quotedEnvDoesNotCreateAnEnvAndJavascriptDuplicate() {
        assertThat(rule.evaluate(file("VITE_API_KEY='"+fake+"'"))).hasSize(1);
    }
    @Test void relatedArgumentMaskingHandlesTabsWithoutLeakingSyntheticValues() {
        assertThat(FrontendEvidenceSanitizer.maskSecrets("localStorage.setItem('token',\t'fixture-value')"))
                .doesNotContain("fixture-value").contains("redacted");
    }
    @Test void engineKeepsHistoricalGenericIdentityForTheSameEnvAssignment() {
        var f=file("VITE_API_KEY="+fake);
        var engine=new com.securedeploy.rule.engine.VulnerabilityRuleEngine(List.of(new HardcodedSecretRule(),rule));
        var matches=engine.execute(new com.securedeploy.rule.engine.RuleExecutionContext(new ProjectStructure(Path.of("."),List.of(f))));
        assertThat(matches).hasSize(1);assertThat(matches.get(0).ruleId()).isEqualTo("HARDCODED_SECRET");
        assertThat(rule.evaluate(file("NEXT_PUBLIC_TOKEN="+fake))).hasSize(1);
        var publicFile=file("VITE_API_KEY=public-client-id");
        assertThat(engine.execute(new com.securedeploy.rule.engine.RuleExecutionContext(new ProjectStructure(Path.of("."),List.of(publicFile))))).isEmpty();
    }
}
