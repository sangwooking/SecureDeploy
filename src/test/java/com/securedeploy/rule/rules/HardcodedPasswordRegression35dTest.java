package com.securedeploy.rule.rules;

import com.securedeploy.project.model.*;
import com.securedeploy.rule.filter.FalsePositiveAnalyzer;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/** Synthetic contract controls, not replacements for the seven unavailable applications. */
class HardcodedPasswordRegression35dTest {
    private final HardcodedPasswordRule rule=new HardcodedPasswordRule();
    private ProjectFile file(String value){
        return new ProjectFile(Path.of("config/application.properties"),"config/application.properties",
                ProjectFileType.PROPERTIES,List.of("db.password="+value));
    }
    @Test void syntheticLiteralRetainsTheExistingRuleThroughFalsePositiveProcessing(){
        String synthetic="N4f7zP8w"+"K2m9vR6s";
        var input=file(synthetic);var raw=rule.evaluate(input);
        assertThat(raw).hasSize(1).allSatisfy(m->assertThat(m.ruleId()).isEqualTo("HARDCODED_PASSWORD"));
        var filtered=new FalsePositiveAnalyzer().analyze(new ProjectStructure(Path.of("."),List.of(input)),raw);
        assertThat(filtered).hasSize(1).allSatisfy(m->{
            assertThat(m.ruleId()).isEqualTo("HARDCODED_PASSWORD");
            assertThat(m.filePath()).isEqualTo(input.relativePath());
            assertThat(m.line()).isEqualTo(1);
            assertThat(m.evidence()).doesNotContain(synthetic);
        });
    }
    @Test void environmentReferencesAndMaskedValuesDoNotBecomeLiteralPasswords(){
        for(String value:List.of("${DB_PASSWORD}","********","XXXXXXXX"))
            assertThat(rule.evaluate(file(value))).isEmpty();
    }
    @Test void thisConfigurationRuleDoesNotInventAJavaScriptPasswordContract(){
        var input=new ProjectFile(Path.of("screen.tsx"),"screen.tsx",ProjectFileType.REACT,
                List.of("const password = form.password;"));
        assertThat(rule.evaluate(input)).isEmpty();
    }
}
