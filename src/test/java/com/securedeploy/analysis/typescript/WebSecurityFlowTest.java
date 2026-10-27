package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class WebSecurityFlowTest {
    final TypeScriptServerAnalyzer analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
    private ProjectStructure input(String setup,String body) {
        return new ProjectStructure(Path.of("/unreadable"),List.of(
            new ProjectFile(Path.of("/unreadable/server.cjs"),"server.cjs",ProjectFileType.JAVASCRIPT,
                List.of("const app=require('express')();const cors=require('cors');const session=require('express-session');",setup,
                    "app.get('/a',(req,res)=>{"+body+"});","app.get('/b',(req,res)=>{"+body+"});")),
            new ProjectFile(Path.of("/unreadable/package.json"),"package.json",ProjectFileType.PACKAGE_JSON,
                List.of("{\"dependencies\":{\"express\":\"4.18.0\",\"cors\":\"2.8.5\",\"express-session\":\"1.18.1\"}}"))));
    }
    @Test void sharedModulePolicyGroupsOnlyCorroboratedResponseLocations() {
        var r=analyzer.analyze(input("app.use(cors({origin:true,credentials:true}));","res.json({value:process.env.SERVICE_ROLE_KEY});"));
        var findings=r.validatedFindings().stream().filter(f->f.ruleId().equals("JS_CORS_CREDENTIAL_REFLECTION")).toList();
        assertThat(findings).hasSize(1);
        var f=findings.get(0);
        assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(f.executionLocations()).hasSize(2);
        assertThat(f.evidence()).hasSize(2);
        var converter=new ServerAnalysisConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(r))).isEqualTo(r);
    }
    @Test void sessionCookieFindingRequiresAppliedSessionReference() {
        var r=analyzer.analyze(input("app.use(session({secret:process.env.SESSION_SECRET,cookie:{secure:true,httpOnly:false}}));",
            "const current=req.session;res.end('ok');"));
        assertThat(r.validatedFindings()).hasSize(1);
        assertThat(r.validatedFindings().get(0).ruleId()).isEqualTo("JS_SESSION_COOKIE_ATTRIBUTE_REVIEW");
        assertThat(r.validatedFindings().get(0).executionLocations()).hasSize(2);
    }
    @Test void unknownMiddlewareAndPublicResponseDoNotBecomeCorsFindings() {
        for(String setup:List.of("app.use(cors({origin:true,credentials:true}));app.use(externalGate);",
            "app.use(cors({origin:'https://trusted.invalid',credentials:true}));")) {
            assertThat(analyzer.analyze(input(setup,"res.json({public:true});")).validatedFindings()).isEmpty();
        }
    }
}
