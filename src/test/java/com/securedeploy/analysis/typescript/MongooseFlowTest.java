package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class MongooseFlowTest {
    static final String FIELD_PREFIX="const app=require('express')();const m=require('mongoose');const checks=require('validator');const Model=m.model('Account',new m.Schema({login:String,pass:String}));app.post('/',(req,res)=>{";
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
        assertThat(result.analyzerVersion()).isEqualTo("ts-server-v44");
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
    @Test void repeatedFilterAliasesAreNotCyclesAndSafeAliasesRemainData(){
        var risk=analyze("const x=req.body;await Model.findOne({email:x,another:x});","6.13.0");
        assertThat(risk.validatedFindings()).hasSize(1);
        assertThat(risk.validatedFindings().get(0).comparisonPolicy()).isEqualTo("NOT_COMPARED");
        var safe=analyze("const x='fixed';await Model.findOne({email:x,another:x});","6.13.0");
        assertThat(safe.validatedFindings()).isEmpty();
        assertThat(safe.nodeUses()).anyMatch(u->u.kind().equals("STATIC_OR_STRING_FILTER"));
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(risk);
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(risk);
        assertThat(json).doesNotContain("const x=req.body");
    }
    @Test void callbackExecutionIsVersionAwareAndRepeatsDoNotDuplicateTheUserWarning() {
        for(String version:List.of("4.13.0","5.13.0","6.13.0")){
            var r=analyze("const q=Model.findOne({email:req.body.email});const done=(err,row)=>{};q.exec(done);q.exec(done);await q;",version);
            assertThat(r.validatedFindings()).hasSize(1).allSatisfy(f->{
                assertThat(f.executionLocations()).hasSize(1).allMatch(l->l.kind().equals("MONGOOSE_CALLBACK_EXECUTION_REQUEST"));
                assertThat(f.evidence().get(0).flow()).anyMatch(l->l.kind().equals("MONGOOSE_CALLBACK_REFERENCE"));
                assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
            });
        }
        for(String version:List.of("7.3.0","8.3.0")){
            var r=analyze("await Model.findOne({email:req.body.email},(err,row)=>{});",version);
            assertThat(r.validatedFindings()).isEmpty();
            assertThat(r.nodeUses()).anyMatch(u->u.kind().equals("CALLBACK_VERSION_UNSUPPORTED"));
        }
        var separate=analyze("Model.findOne({email:req.body.first},()=>{});Model.findOne({email:req.body.second},()=>{});","6.13.0");
        assertThat(separate.validatedFindings()).hasSize(2);
    }
    @Test void sharedQueryLocationRetainsDistinctSourceEvidenceInOneUserFinding() {
        var result=analyze("function query(email){Model.findOne({email},()=>{});}query(req.body.first);query(req.body.second);","6.13.0");
        assertThat(result.validatedFindings()).hasSize(1);
        assertThat(result.validatedFindings().get(0).evidence()).hasSize(2);
        assertThat(result.validatedFindings().get(0).evidence().stream().map(f->f.source().column()).distinct().count()).isEqualTo(2);
    }
    ServerAnalysisSnapshot fields(String body,String validatorVersion) {
        var sources=Map.of("package.json","{\"dependencies\":{\"mongoose\":\"4.2.4\",\"express\":\"4.18.0\",\"validator\":\""+validatorVersion+"\"}}",
            "server.cjs",FIELD_PREFIX+body+"});");
        var files=sources.entrySet().stream().map(e->new ProjectFile(Path.of(e.getKey()),e.getKey(),
            e.getKey().endsWith(".json")?ProjectFileType.PACKAGE_JSON:ProjectFileType.JAVASCRIPT,e.getValue().lines().toList())).toList();
        return analyzer.analyze(new ProjectStructure(Path.of("/not-readable"),files));
    }
    @Test void fieldScopedFormatEvidenceReachesUserFindingWithoutCertifyingAnotherField() {
        String body="if(checks.isEmail(req.body.contact)){Model.findOne({login:req.body.contact,pass:req.body.credential},()=>{});}";
        var result=fields(body,"^13.5.2");
        assertThat(result.validatedFindings()).hasSize(1);
        var finding=result.validatedFindings().get(0);
        var evidence=finding.evidence().get(0);
        assertThat(evidence.source().kind()).isEqualTo("HTTP_FIELD_SOURCE");
        assertThat(evidence.source().column()).isEqualTo(FIELD_PREFIX.length()+1+body.indexOf("req.body.credential"));
        assertThat(evidence.defenses()).anyMatch(l->l.kind().equals("FIELD_EMAIL_ACCEPTED_BRANCH"));
        assertThat(finding.recommendedAction()).contains("typeof value !== \"string\"","입력 필드마다","현재 저장 방식이나 공격 성공을 확인한 것은 아닙니다");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(fields(body,"latest").validatedFindings()).isEmpty();
        assertThat(fields(body,"latest").nodeUses()).anyMatch(u->u.kind().equals("UNKNOWN"));
    }
    @Test void perFieldPrimitiveGuardsAndFormatOnlyHaveDifferentOutcomes() {
        var strings=fields("if(typeof req.body.contact!=='string')return;if(typeof req.body.credential!=='string')return;Model.findOne({login:req.body.contact,pass:req.body.credential},()=>{});","13.5.2");
        assertThat(strings.validatedFindings()).isEmpty();
        assertThat(strings.nodeUses()).anyMatch(u->u.kind().equals("STATIC_OR_STRING_FILTER"));
        var format=fields("if(checks.isEmail(req.body.contact)){Model.findOne({login:req.body.contact},()=>{});}","13.5.2");
        assertThat(format.validatedFindings()).isEmpty();
        assertThat(format.nodeUses()).anyMatch(u->u.kind().equals("UNKNOWN"));
    }
}
