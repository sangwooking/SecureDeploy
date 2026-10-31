package com.securedeploy.analysis.typescript;
import static org.junit.jupiter.api.Assertions.*;import org.junit.jupiter.api.Test;import java.util.*;import com.fasterxml.jackson.databind.*;
class WorkerV55IntegrationTest {
 ServerAnalysisSnapshot run(String body){return new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new WorkerV53IntegrationTest().project(Map.of("package.json","{\"type\":\"module\",\"dependencies\":{\"express\":\"4.21.2\"}}","entry.mjs","import express from 'express';const app=express();app.get('/view',(req,res)=>{"+body+"});")));}
 @Test void htmlFindingRequiresSourceSinkAndMatchingProofObservation()throws Exception{
  var r=run("res.send(`<p>${req.query.name}</p>`);");assertEquals("ts-server-v55",r.analyzerVersion());assertEquals(1,r.validatedFindings().size());var f=r.validatedFindings().get(0);assertEquals("HTTP_HTML_INPUT_FLOW",f.ruleId());assertEquals("REVIEW_REQUIRED",f.priority().name());assertEquals("NOT_COMPARED",f.comparisonPolicy());assertTrue(f.riskExplanation().contains("CWE-79"));assertTrue(f.recommendedAction().contains("text/plain"));
  var mapper=new ObjectMapper();var raw=(com.fasterxml.jackson.databind.node.ObjectNode)mapper.valueToTree(r);raw.putArray("nodeUses");var missing=mapper.treeToValue(raw,ServerAnalysisSnapshot.class);assertTrue(ServerFlowFinding.connect(missing).isEmpty());
  raw=(com.fasterxml.jackson.databind.node.ObjectNode)mapper.valueToTree(r);((com.fasterxml.jackson.databind.node.ObjectNode)raw.path("findings").get(0).path("source")).put("kind","UNVERIFIED");assertTrue(ServerFlowFinding.connect(mapper.treeToValue(raw,ServerAnalysisSnapshot.class)).isEmpty());
 }
 @Test void normalResponseAndLegacyReviewStayUnpromoted()throws Exception{
  for(String body:List.of("res.type('text/plain').send(req.query.name);","res.json({name:req.query.name});","res.send('<p>fixed</p>');","res.send(sanitize(req.query.name));"))assertTrue(run(body).validatedFindings().isEmpty(),body);
  var r=run("res.send(`<p>${req.query.name}</p>`);");var c=new ServerAnalysisConverter();String json=c.convertToDatabaseColumn(r);assertEquals(r,c.convertToEntityAttribute(json));
  var mapper=new ObjectMapper();var old=(com.fasterxml.jackson.databind.node.ObjectNode)mapper.readTree(json);old.put("analyzerVersion","ts-server-v54");old.putArray("findings");old.putArray("validatedFindings");var uses=old.withArray("nodeUses");for(int i=uses.size()-1;i>=0;i--)if(uses.get(i).path("ruleId").asText().equals("HTTP_HTML_INPUT_FLOW"))uses.remove(i);
  var hydrated=c.convertToEntityAttribute(old.toString());assertEquals("ts-server-v54",hydrated.analyzerVersion());assertTrue(hydrated.validatedFindings().isEmpty());
 }
 @Test void returnedNextResponsePassesTheMatchedBackendGate(){var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new WorkerV53IntegrationTest().project(Map.of("package.json","{\"dependencies\":{\"next\":\"15.3.0\"}}","app/api/view/route.ts","export function GET(req){return new Response(new URL(req.url).searchParams.get('q'),{headers:{'Content-Type':'text/html'}});}")));assertEquals(1,r.validatedFindings().stream().filter(f->f.ruleId().equals("HTTP_HTML_INPUT_FLOW")).count());}
}
