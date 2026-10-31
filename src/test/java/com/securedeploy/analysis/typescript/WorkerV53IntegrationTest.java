package com.securedeploy.analysis.typescript;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;import org.junit.jupiter.api.Test;
class WorkerV53IntegrationTest {
 com.securedeploy.project.model.ProjectStructure project(Map<String,String> sources){return new com.securedeploy.project.model.ProjectStructure(java.nio.file.Path.of("/synthetic-not-executable"),sources.entrySet().stream().map(e->new com.securedeploy.project.model.ProjectFile(java.nio.file.Path.of(e.getKey()),e.getKey(),e.getKey().endsWith("json")?com.securedeploy.project.model.ProjectFileType.PACKAGE_JSON:com.securedeploy.project.model.ProjectFileType.TYPESCRIPT,e.getValue().lines().toList())).toList());}
 @Test void pagesImportedDefaultKeepsEntryAndSinkInSeparateFiles(){
  var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project(Map.of(
   "package.json","{\"dependencies\":{\"next\":\"15.3.0\"}}",
   "pages/api/check.ts","export {default} from '../../handler.ts';",
   "handler.ts","export default function check(req,res){eval(req.query.code);res.json({ok:true});}")));
  assertEquals("ts-server-v53",r.analyzerVersion());
  assertTrue(r.nodeUses().stream().anyMatch(n->n.operation().equals("NEXT_PAGES_DEFAULT_HANDLER")&&n.location().filePath().equals("pages/api/check.ts")));
  assertTrue(r.validatedFindings().stream().anyMatch(f->f.ruleId().equals("JS_EVAL_INPUT_FLOW")&&f.location().filePath().equals("handler.ts")));
  assertEquals("PARTIAL",r.status());
 }
 @Test void htmlInputIsReviewEvidenceWithoutNewFindingOrRisk(){
  var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project(Map.of(
   "package.json","{\"type\":\"module\",\"dependencies\":{\"express\":\"4.21.2\"}}",
   "entry.mjs","import express from 'express';const app=express();app.get('/',(req,res)=>res.send(`<p>${req.query.name}</p>`));")));
  assertEquals("ts-server-v53",r.analyzerVersion());
  assertTrue(r.nodeUses().stream().anyMatch(n->n.kind().equals("HTML_RESPONSE_INPUT_CANDIDATE")&&!n.trace().isEmpty()));
  assertTrue(r.validatedFindings().isEmpty());
 }
}
