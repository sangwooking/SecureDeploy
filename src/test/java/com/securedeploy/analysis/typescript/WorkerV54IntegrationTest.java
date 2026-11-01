package com.securedeploy.analysis.typescript;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;import java.util.*;
class WorkerV54IntegrationTest {
 @Test void htmlContextCrossFileRoundTripPreservesFlowAndVersion(){
  var p=new WorkerV53IntegrationTest().project(Map.of("package.json","{\"type\":\"module\",\"dependencies\":{\"express\":\"4.21.2\"}}","entry.mjs","import express from 'express';import {render} from './view.mjs';const app=express();app.get('/',(req,res)=>res.send(render(req.query.name)));","view.mjs","export function render(name){return `<b>${name}</b>`;}"));
  var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(p);
  assertEquals("ts-server-v56",r.analyzerVersion());
  var h=r.nodeUses().stream().filter(n->n.kind().equals("HTML_RESPONSE_INPUT_CANDIDATE")).findFirst().orElseThrow();
  assertTrue(h.trace().stream().anyMatch(l->l.kind().equals("HTML_OUTPUT_CONTEXT_HTML_TEXT")));
  assertTrue(h.trace().stream().anyMatch(l->l.kind().equals("HTML_FUNCTION_RETURN")&&l.filePath().equals("view.mjs")));
  assertTrue(r.validatedFindings().stream().anyMatch(f->f.ruleId().equals("HTTP_HTML_INPUT_FLOW")));var c=new ServerAnalysisConverter();String json=c.convertToDatabaseColumn(r);assertEquals(r,c.convertToEntityAttribute(json));
  assertEquals("ts-server-v53",c.convertToEntityAttribute(json.replace("ts-server-v56","ts-server-v53")).analyzerVersion());
 }
}
