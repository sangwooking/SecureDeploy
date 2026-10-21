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
}
