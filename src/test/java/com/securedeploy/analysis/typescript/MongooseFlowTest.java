package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class MongooseFlowTest {
    final TypeScriptServerAnalyzer analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
    ServerAnalysisSnapshot analyze(String body,String version) {
        var sources=Map.of("package.json","{\"dependencies\":{\"mongoose\":\""+version+"\",\"express\":\"4.18.0\"}}",
            "server.cjs","const express=require('express');const m=require('mongoose');const Model=m.model('Record',new m.Schema({email:String}));const app=express();app.post('/',async(req,res)=>{"+body+"res.end('ok');});");
        var files=sources.entrySet().stream().map(e->new ProjectFile(Path.of(e.getKey()),e.getKey(),
            e.getKey().endsWith(".json")?ProjectFileType.PACKAGE_JSON:ProjectFileType.JAVASCRIPT,e.getValue().lines().toList())).toList();
        return analyzer.analyze(new ProjectStructure(Path.of("/not-readable"),files));
    }
    @Test void modelOriginAndConsumedInputProduceSupplementalFindingWithExactEvidence() {
        var result=analyze("const email=req.body.email;await Model.findOne({email});","6.13.0");
        assertThat(result.analyzerVersion()).isEqualTo("ts-server-v29");
        assertThat(result.validatedFindings()).hasSize(1).allSatisfy(f->{
            assertThat(f.ruleId()).isEqualTo("JS_MONGOOSE_SELECTOR_INPUT_FLOW");
            assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");
            assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
            assertThat(f.executionLocations()).hasSize(1);
            assertThat(f.evidence().get(0).flow()).anyMatch(l->l.kind().equals("EXPRESS_BODY"));
            assertThat(f.title()).doesNotContain("실행 문자열");
        });
        var converter=new ServerAnalysisConverter();
        var stored=converter.convertToDatabaseColumn(result);
        assertThat(converter.convertToDatabaseColumn(converter.convertToEntityAttribute(stored))).isEqualTo(stored);
        assertThat(stored).doesNotContain("Record");
    }
    @Test void defensesUnknownAndUnconsumedQueriesDoNotBecomeUserFindings() {
        for(String body:List.of("await Model.findOne({email:String(req.body.email)});",
            "await Model.findOne({email:req.body.email}).setOptions({sanitizeFilter:true});",
            "await Model.findOne({email:req.body.email.toString()});","Model.findOne(req.body);")) {
            var r=analyze(body,"6.13.0");assertThat(r.validatedFindings()).isEmpty();
            assertThat(r.nodeUses()).anyMatch(u->u.ruleId().equals("JS_MONGOOSE_SELECTOR_INPUT_FLOW"));
        }
        assertThat(analyze("await Model.findOne(req.body);","latest").nodeUses()).anyMatch(u->u.kind().equals("UNKNOWN"));
        assertThat(analyze("await Model.findOne({email:req.body.email},null,{sanitizeFilter:true});","5.13.0").validatedFindings()).isEmpty();
    }
}
