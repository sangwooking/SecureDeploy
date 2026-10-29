package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static com.securedeploy.analysis.typescript.TypeScriptServerAnalyzerTest.*;

class ServerFlowFindingTest {
    final TypeScriptServerAnalyzer analyzer = new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());

    @Test void httpListenerAdapterReachesExistingFindingWithoutChangingComparisonPolicy() {
        String start="const express=require('express'),http=require('node:http');const app=express();new http.Server(app);";
        var risky=analyzer.analyze(project(start+"app.post('/',(req,res)=>eval(req.body.value));"));
        assertThat(risky.analyzerVersion()).isEqualTo("ts-server-v50");
        assertThat(risky.validatedFindings()).hasSize(1);
        var finding=risky.validatedFindings().get(0);
        assertThat(finding.ruleId()).isEqualTo("JS_EVAL_INPUT_FLOW");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(finding.evidence().get(0).source().kind()).isEqualTo("EXPRESS_BODY");
        assertThat(finding.evidence().get(0).sink().kind()).isEqualTo("EVAL_CALL");
        assertThat(analyzer.analyze(project(start+"app.post('/',(req,res)=>eval(1));")).validatedFindings()).isEmpty();
    }

    @Test void hrefReplacementReachesSnapshotAndGuideWithoutReclassifyingOldSnapshots() {
        String prefix="const app=require('express')();const http=require('node:http');app.post('/',(req,res)=>{const u=new URL(req.body.url);if(u.protocol!=='http:'||u.hostname!=='a.example.invalid')return;";
        var changed=analyzer.analyze(project(prefix+"u.href=req.body.other;http.get(u);});"));
        assertThat(changed.validatedFindings()).hasSize(1);
        var finding=changed.validatedFindings().get(0);
        assertThat(finding.ruleId()).isEqualTo("TS_SSRF_INPUT_FLOW");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(finding.recommendedAction()).contains("마지막 URL 변경 이후");
        assertThat(finding.evidence().get(0).source().column()).isGreaterThan(150);
        assertThat(changed.httpUses().get(0).defenses()).isEmpty();
        var converter=new ServerAnalysisConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(changed))).isEqualTo(changed);
        for(String suffix:List.of("http.get(u);});","u.href='http://fixed.example.invalid/';http.get(u);});"))
            assertThat(analyzer.analyze(project(prefix+suffix)).validatedFindings()).isEmpty();
    }

    @Test void builtinGetConnectsRequestInputWithoutPromotingUnsupportedOverloads() {
        String start="const app=require('express')();const http=require('node:http');app.post('/',(req,res)=>{";
        var risky=analyzer.analyze(project(start+"http.get(new URL(req.body.url,'http://fixed.example.invalid/'));});"));
        assertThat(risky.validatedFindings()).hasSize(1);
        var finding=risky.validatedFindings().get(0);
        assertThat(finding.ruleId()).isEqualTo("TS_SSRF_INPUT_FLOW");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(finding.evidence().get(0).source().kind()).isEqualTo("EXPRESS_BODY");
        assertThat(finding.executionLocations().get(0).kind()).isEqualTo("HTTP_REQUEST_CALL");
        for(String body:List.of("http.get('http://fixed.example.invalid/');",
                "http.get(req.body.url,{lookup:external});", "http.get(req.body.url,()=>{});",
                "http.get=external;http.get(req.body.url);"))
            assertThat(analyzer.analyze(project(start+body+"});")).validatedFindings()).isEmpty();
    }

    @Test void provenShellInputReachesSupplementalFindingButUnknownOptionsAndArgvDoNot() {
        String start="const express=require('express');const app=express();const cp=require('node:child_process');app.post('/work',(req,res)=>{";
        var snapshot=analyzer.analyze(project(start+"const input=req.body.value;cp.exec('fixed '+input);});"));
        assertThat(snapshot.validatedFindings()).hasSize(1);
        var finding=snapshot.validatedFindings().get(0);
        assertThat(finding.ruleId()).isEqualTo("JS_SHELL_COMMAND_INPUT_FLOW");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(finding.title()).contains("명령 문자열");
        assertThat(finding.evidence().get(0).kind()).isEqualTo("CWE-78");
        assertThat(finding.evidence().get(0).source().kind()).isEqualTo("EXPRESS_BODY");
        assertThat(finding.executionLocations().get(0).kind()).isEqualTo("NODE_EXEC_SHELL");
        assertThat(finding.recommendedAction()).contains("인자 주입");
        var converter=new ServerAnalysisConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(snapshot))).isEqualTo(snapshot);
        for(String body:new String[]{"cp.exec('fixed');", "cp.exec(transform(req.body.value));", "cp.exec(req.body.value,options);",
                "cp.execSync(req.body.value,()=>{});", "cp.execFile('fixed',['arg',req.body.value]);"})
            assertThat(analyzer.analyze(project(start+body+"});")).validatedFindings()).isEmpty();
    }

    @Test void ssrfConnectsOnlyKnownDestinationFlowsAndPreservesSqlPolicy() {
        String start = "export default {fetch(request,env){const url=new URL(request.url).searchParams.get('url'); ";
        var snapshot = analyzer.analyze(project(start + "env.DB.prepare(url).all(); return fetch(new Request(url));}}"));
        assertThat(snapshot.validatedFindings()).hasSize(2).allSatisfy(f -> {
            assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");
            assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
            assertThat(f.executionLocations()).isNotEmpty();
        });
        assertThat(snapshot.validatedFindings()).extracting(ServerFlowFinding::ruleId).containsExactly("TS_SQL_INPUT_FLOW", "TS_SSRF_INPUT_FLOW");
        assertThat(snapshot.httpUses().get(0).kind()).isEqualTo("INPUT_IN_DESTINATION");
        for (String expression : new String[] {"normalize(url)", "'https://api.example.invalid/?q='+url"})
            assertThat(analyzer.analyze(project(start+"return fetch("+expression+");}}")).validatedFindings()).isEmpty();
        var converter = new ServerAnalysisConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(snapshot))).isEqualTo(snapshot);
    }

    @Test void oldHttpCoverageIsMissingNotInvented() throws Exception {
        var tree = new ObjectMapper().readTree(new ServerAnalysisConverter().convertToDatabaseColumn(analyzer.analyze(project(UNSAFE))));
        ((com.fasterxml.jackson.databind.node.ObjectNode) tree).remove("httpUses");
        ((com.fasterxml.jackson.databind.node.ObjectNode) tree).put("analyzerVersion", "ts-server-v3");
        var old = new ServerAnalysisConverter().convertToEntityAttribute(tree.toString());
        assertThat(old.httpUses()).isNull();
        assertThat(old.analyzerVersion()).isEqualTo("ts-server-v3");
    }

    @Test void expressionStateCorrectionReachesValidatedFindingsWithoutChangingTheirPolicy() {
        String start = "export default { fetch(request,env) { let id = new URL(request.url).searchParams.get('id'); ";
        var unsafe = analyzer.analyze(project(start + "return env.DB.prepare(id + (id = '0')).all(); }}"));
        var safe = analyzer.analyze(project(start + "return env.DB.prepare((id = '0') + id).all(); }}"));
        assertThat(unsafe.analyzerVersion()).isEqualTo("ts-server-v50");
        assertThat(unsafe.validatedFindings()).hasSize(1).allSatisfy(f -> {
            assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");
            assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        });
        assertThat(safe.validatedFindings()).isEmpty();
    }

    @Test void v2SnapshotsRemainImmutableAndAreNotReconnectedByTheNewAnalyzer() {
        var converter = new ServerAnalysisConverter();
        var snapshot = analyzer.analyze(project(UNSAFE));
        for(String version:List.of("ts-server-v2","ts-server-v24","ts-server-v25","ts-server-v26","ts-server-v27","ts-server-v28","ts-server-v29","ts-server-v30","ts-server-v31","ts-server-v32","ts-server-v33","ts-server-v34","ts-server-v35","ts-server-v36","ts-server-v37","ts-server-v38","ts-server-v39","ts-server-v40","ts-server-v41","ts-server-v42","ts-server-v43","ts-server-v44","ts-server-v45","ts-server-v46","ts-server-v47","ts-server-v48","ts-server-v49")){
            String previous = converter.convertToDatabaseColumn(snapshot).replace("ts-server-v50",version);
            var old = converter.convertToEntityAttribute(previous);
            assertThat(old.analyzerVersion()).isEqualTo(version);
            assertThat(converter.convertToDatabaseColumn(old)).isEqualTo(previous);
            assertThat(old.validatedFindings()).allSatisfy(f -> assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED"));
        }
    }

    @Test void knownInputQueryAndExecutionBecomeOneSupplementalFinding() {
        var result = analyzer.analyze(project(UNSAFE));
        var finding = result.validatedFindings().get(0);
        assertThat(result.validatedFindings()).hasSize(1);
        assertThat(finding.findingId()).startsWith("ts-flow:");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.sourceType()).isEqualTo("TYPESCRIPT_DATA_FLOW");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(finding.evidence().get(0).flow()).anyMatch(l -> l.kind().equals("SQL_STRING_CONSTRUCTION"));
        assertThat(finding.executionLocations()).isNotEmpty();
        assertThat(finding.verificationSteps()).hasSize(3);
        assertThat(analyzer.analyze(project(UNSAFE)).validatedFindings().get(0).findingId()).isEqualTo(finding.findingId());
    }
    @Test void unknownTransformNoExecutionAndSafeBindingAreNotPromoted() {
        for (String code : new String[] {SAFE, UNSAFE.replace(".all()", ""),
                UNSAFE.replace("+ id", "+ escapeSql(id)"),
                UNSAFE.replace("return env.DB", "if(!['id','title'].includes(id)) return; return env.DB")}) {
            assertThat(analyzer.analyze(project(code)).validatedFindings()).isEmpty();
        }
        var bindAfterConcat = analyzer.analyze(project(UNSAFE.replace(".all()", ".bind(1).all()")));
        assertThat(bindAfterConcat.validatedFindings()).hasSize(1);
        assertThat(bindAfterConcat.validatedFindings().get(0).evidence().get(0).limitations()).contains("BIND_DOES_NOT_REWRITE_QUERY");
    }
    @Test void multipleInputsToOneSinkAreGroupedWithoutDiscardingTheirPaths() {
        String code = """
                export default {fetch(request, env) {
                  const url = new URL(request.url);
                  query(env.DB,url.searchParams.get('a'));
                  return query(env.DB,url.searchParams.get('b'));
                }};
                function query(db, id) { return db.prepare('SELECT * FROM t WHERE id=' + id).all(); }
                """;
        var snapshot = analyzer.analyze(project(code));
        assertThat(snapshot.findings()).hasSize(2);
        assertThat(snapshot.validatedFindings()).hasSize(1);
        assertThat(snapshot.validatedFindings().get(0).evidence()).hasSize(2);
    }
    @Test void snapshotsRoundTripAndLegacyIsNotReinterpreted() throws Exception {
        var converter = new ServerAnalysisConverter();
        var snapshot = analyzer.analyze(project(UNSAFE));
        String encoded = converter.convertToDatabaseColumn(snapshot);
        assertThat(encoded).doesNotContain("SELECT *", "WHERE id=");
        assertThat(converter.convertToEntityAttribute(encoded)).isEqualTo(snapshot);
        var old = new ObjectMapper().readTree(encoded);
        ((com.fasterxml.jackson.databind.node.ObjectNode) old).remove("validatedFindings");
        ((com.fasterxml.jackson.databind.node.ObjectNode) old).put("analyzerVersion", "ts-server-v1");
        for (var sql : old.path("sqlUses")) ((com.fasterxml.jackson.databind.node.ObjectNode) sql).remove("executionLocations");
        var restored = converter.convertToEntityAttribute(old.toString());
        assertThat(restored.validatedFindings()).isNull();
        assertThat(restored.analyzerVersion()).isEqualTo("ts-server-v1");
        assertThat(restored.findings()).isEqualTo(snapshot.findings());
    }
    @Test void partialExecutionAndUnresolvedGuardsRemainCandidates() {
        for (String body : new String[] {
                "const statement = env.DB.prepare(id); for(let i=0;i<2;i++) { statement.all(); }",
                "if(!isValid(id)) return; return env.DB.prepare(id).all();",
                "const allowed=['id','title']; if(!allowed.includes(id)) return; return env.DB.prepare(id).all();"}) {
            var snapshot = analyzer.analyze(project("export default {fetch(request,env){ const id = new URL(request.url).searchParams.get('id'); " + body + "}}"));
            assertThat(snapshot.findings()).isNotEmpty();
            assertThat(snapshot.validatedFindings()).isEmpty();
        }
    }
}
