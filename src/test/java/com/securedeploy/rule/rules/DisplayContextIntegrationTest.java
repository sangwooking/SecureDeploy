package com.securedeploy.rule.rules;

import com.securedeploy.analysis.typescript.TypeScriptAnalysisProperties;
import com.securedeploy.project.model.*;
import com.securedeploy.rule.engine.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class DisplayContextIntegrationTest {
    private final String provider="""
            import i18n from 'i18next';
            const words={en:{translation:{
              secret:'The Secret Behind Better Service',
              terms:'Read our <b>terms</b>'
            }}};
            i18n.init({resources:words});
            """;
    private List<com.securedeploy.rule.model.RuleMatch> scan(String content,String settings,boolean enabled) {
        var files=List.of(new ProjectFile(Path.of("View.tsx"),"View.tsx",ProjectFileType.REACT,content.lines().toList()),
                new ProjectFile(Path.of("locale.ts"),"locale.ts",ProjectFileType.TYPESCRIPT,settings.lines().toList()));
        var properties=new TypeScriptAnalysisProperties();properties.setEnabled(enabled);
        return new VulnerabilityRuleEngine(List.of(new HardcodedFrontendSecretRule(),new ReactDangerousHtmlRule(),new UnvalidatedRedirectRule()),new InsecureApiUrlContext(properties))
                .execute(new RuleExecutionContext(new ProjectStructure(Path.of("/unreadable-target"),files)));
    }
    @Test void typedTranslationLabelsAndFixedHtmlSuppressOnlyProvenPatternWarnings() {
        String page="import {useTranslation} from 'react-i18next';function View(){const {t}=useTranslation();return <p dangerouslySetInnerHTML={{__html:t('terms')}}/>;}";
        assertThat(scan(page,provider,false)).hasSize(2);
        assertThat(scan(page,provider,true)).isEmpty();
    }
    @Test void dynamicHtmlAndOpaqueCredentialRemainEvenInsideResourceDictionaries() {
        String fake="ghp_"+"z".repeat(36);
        var result=scan("const View=()=> <p dangerouslySetInnerHTML={{__html:request.body}}/>;",provider.replace("The Secret Behind Better Service",fake),true);
        assertThat(result).extracting(com.securedeploy.rule.model.RuleMatch::ruleId).containsExactlyInAnyOrder("REACT_DANGEROUS_HTML","HARDCODED_FRONTEND_SECRET");
        assertThat(result.get(1).evidence()).doesNotContain(fake);
    }
    @Test void actualRequestRedirectAndUnknownMaskRemainButFixedDestinationIsNotUserControl() {
        assertThat(scan("const redirectUrl=request.query.next;window.location.href=redirectUrl;","",true)).hasSize(1);
        assertThat(scan("const redirectUrl=check(request.query.next);window.location.href=redirectUrl;","",true)).hasSize(1);
        assertThat(scan("const redirectUrl='/home';window.location.href=redirectUrl;","",true)).isEmpty();
    }
    @Test void staticAliasesAreExcludedButActiveFixedMarkupAndUnknownInputsRetainEvidence() {
        assertThat(scan("const text='Read <b>terms</b>';const View=()=> <div dangerouslySetInnerHTML={{__html:text}}/>;","",true)).isEmpty();
        for(String value:List.of("\"<img src=x onerror=alert(1)>\"","request.body","sanitize(request.body)")) {
            var result=scan("const View=()=> <div dangerouslySetInnerHTML={{__html:"+value+"}}/>;","",true);
            assertThat(result).hasSize(1);
            assertThat(result.get(0).analysisNote()).contains("HTML_CONTEXT=");
            var file=new ProjectFile(Path.of("View.tsx"),"View.tsx",ProjectFileType.REACT,List.of(""));
            var filtered=new com.securedeploy.rule.filter.FalsePositiveAnalyzer().analyze(new ProjectStructure(Path.of("/unreadable-target"),List.of(file)),result);
            assertThat(filtered).hasSize(1);
            assertThat(filtered.get(0).analysisNote()).contains("HTML_CONTEXT=", "외부 입력 연결");
            assertThat(filtered.get(0).confidence()).isEqualTo(com.securedeploy.rule.model.DetectionConfidence.HIGH);
        }
    }
}
