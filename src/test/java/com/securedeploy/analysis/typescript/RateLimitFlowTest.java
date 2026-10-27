package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class RateLimitFlowTest {
    final TypeScriptServerAnalyzer analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
    ProjectStructure input(String options) {
        return new ProjectStructure(Path.of("/unreadable"),List.of(
            new ProjectFile(Path.of("/unreadable/server.cjs"),"server.cjs",ProjectFileType.JAVASCRIPT,List.of(
                "const app=require('express')();const rateLimit=require('express-rate-limit');const fs=require('fs');",
                "app.use(rateLimit("+options+"));",
                "app.post('/a',(req,res)=>{fs.writeFileSync('/owned/state',req.body.value);res.json({ok:true});});",
                "app.post('/b',(req,res)=>{fs.writeFileSync('/owned/other',req.body.value);res.json({ok:true});});")),
            new ProjectFile(Path.of("/unreadable/package.json"),"package.json",ProjectFileType.PACKAGE_JSON,List.of(
                "{\"dependencies\":{\"express\":\"4.18.0\",\"express-rate-limit\":\"7.5.0\"}}"))));
    }
    @Test void corroboratedPolicyFailureGroupsSharedConfigurationWithoutRiskPromotion() {
        var r=analyzer.analyze(input("{limit:3,skip:()=>true}"));
        assertThat(r.analyzerVersion()).isEqualTo("ts-server-v39");
        assertThat(r.validatedFindings()).hasSize(1);var f=r.validatedFindings().get(0);
        assertThat(f.ruleId()).isEqualTo("JS_RATE_LIMIT_BYPASS_REVIEW");
        assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(f.executionLocations()).hasSize(2);assertThat(f.evidence()).hasSize(2);
        var converter=new ServerAnalysisConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(r))).isEqualTo(r);
    }
    @Test void ordinaryRateLimitsAndUnknownKeysNeverBecomeVulnerabilities() {
        for(String opts:List.of("{limit:3}","{limit:0}","{limit:3,keyGenerator:req=>req.user.id}","{limit:3,store:externalStore}")) {
            var r=analyzer.analyze(input(opts));assertThat(r.validatedFindings()).isEmpty();
            assertThat(r.nodeUses()).anyMatch(u->u.ruleId().equals("JS_RATE_LIMIT_CONTEXT"));
        }
    }
}
