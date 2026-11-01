package com.securedeploy.analysis.typescript;
import static org.junit.jupiter.api.Assertions.*;
import com.securedeploy.project.model.*;import java.nio.file.Path;import java.util.*;import org.junit.jupiter.api.Test;
class Epic01HandlerIntegrationTest {
 ProjectStructure project(Map<String,String> source){return new ProjectStructure(Path.of("/not-an-executable-project"),source.entrySet().stream().map(e->new ProjectFile(Path.of(e.getKey()),e.getKey(),e.getKey().endsWith("json")?ProjectFileType.PACKAGE_JSON:ProjectFileType.TYPESCRIPT,e.getValue().lines().toList())).toList());}
 @Test void namespaceFindingSurvivesRestrictedWorkerValidationAndHasCalleeFileEvidence(){
  var p=project(Map.of("package.json","{\"type\":\"module\",\"dependencies\":{\"express\":\"4.21.2\"}}","entry.mjs","import express from 'express';import * as h from './handlers.mjs';const app=express();app.post('/lookup',h.lookup);","handlers.mjs","import {read} from './read.mjs';export function lookup(req,res){eval(read(req.body.code));}","read.mjs","export function read(input){return input;}"));
  var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(p);assertEquals("ts-server-v60",r.analyzerVersion());
  var f=r.validatedFindings().stream().filter(x->x.ruleId().equals("JS_EVAL_INPUT_FLOW")).findFirst().orElseThrow();assertEquals("REVIEW_REQUIRED",f.priority().name());assertEquals("NOT_COMPARED",f.comparisonPolicy());
  assertTrue(f.evidence().get(0).flow().stream().anyMatch(l->l.filePath().equals("read.mjs")&&l.kind().equals("FUNCTION_PARAMETER")));
  assertTrue(r.nodeUses().stream().anyMatch(x->x.kind().equals("ENTRY_REGISTERED")&&x.location().filePath().equals("entry.mjs")));
  var repeat=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(p);assertEquals(r.validatedFindings(),repeat.validatedFindings());
 }
 @Test void nextNamedExportRegistersRouteWhileSinkKeepsItsRealFile(){
  var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project(Map.of("package.json","{\"dependencies\":{\"next\":\"15.3.0\"}}","app/api/relay/route.ts","export {relay as GET} from '../../services/relay.ts';","app/services/relay.ts","export function relay(req:Request){return fetch(new URL(req.url).searchParams.get('target'));}")));
  assertEquals(1,r.validatedFindings().size());assertEquals("app/services/relay.ts",r.validatedFindings().get(0).location().filePath());assertEquals("app/api/relay/route.ts",r.authorizationContexts().get(0).entry().filePath());
  assertEquals("PARTIAL",r.files().stream().filter(f->f.filePath().equals("app/api/relay/route.ts")).findFirst().orElseThrow().flowStatus());
 }
 @Test void selectionOmissionsAndParseFailuresRemainDifferent(){
  var sources=new TreeMap<String,String>();for(int i=0;i<105;i++)sources.put("general/file"+String.format("%03d",i)+".ts","export const x=1;");
  sources.put("entry.mjs","import express from 'express';import * as h from './handlers.mjs';const app=express();app.get('/',h.read);");sources.put("handlers.mjs","export function read(req,res){eval(req.query.code);}");sources.put("broken.ts","export function broken( {");
  var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project(sources));assertEquals(108,r.selectionCoverage().discoveredFiles());assertEquals(100,r.selectionCoverage().submittedFiles());assertEquals(8,r.selectionCoverage().omittedFiles());
  assertEquals("PARTIAL",r.status());assertTrue(r.selectionCoverage().omissionReasons().containsKey("SOURCE_FILE_COUNT_LIMIT"));
  var bad=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project(Map.of("broken.ts","export function broken( {")));assertEquals("PARSE_FAILED",bad.files().get(0).parseStatus());assertEquals(0,bad.selectionCoverage().omittedFiles());
 }
}
