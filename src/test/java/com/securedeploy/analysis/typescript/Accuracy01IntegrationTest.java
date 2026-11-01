package com.securedeploy.analysis.typescript;
import static org.junit.jupiter.api.Assertions.*;import org.junit.jupiter.api.Test;import java.util.*;import com.fasterxml.jackson.databind.*;import com.fasterxml.jackson.databind.node.*;
class Accuracy01IntegrationTest {
 @Test void supportedAttributeWitnessSurvivesBackendAndRejectsMissingOrMixedProof()throws Exception{
  var r=new WorkerV55IntegrationTest().run("res.send(`<p title=\"${req.query.name}\">card</p>`);");
  assertEquals("ts-server-v60",r.analyzerVersion());assertEquals(1,r.validatedFindings().size());assertTrue(r.validatedFindings().get(0).recommendedAction().contains("srcdoc"));
  var m=new ObjectMapper();var raw=(ObjectNode)m.valueToTree(r);raw.putArray("nodeUses");assertTrue(ServerFlowFinding.connect(m.treeToValue(raw,ServerAnalysisSnapshot.class)).isEmpty());
  raw=(ObjectNode)m.valueToTree(r);for(var f:raw.withArray("findings"))for(var l:f.withArray("flow"))if(l.path("kind").asText().equals("QUOTED_INERT_ATTRIBUTE_TITLE"))((ObjectNode)l).put("kind","QUOTED_INERT_ATTRIBUTE_HREF");assertTrue(ServerFlowFinding.connect(m.treeToValue(raw,ServerAnalysisSnapshot.class)).isEmpty());
  var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(r);assertEquals(r,converter.convertToEntityAttribute(json));assertEquals("ts-server-v58",converter.convertToEntityAttribute(json.replace("ts-server-v60","ts-server-v58")).analyzerVersion());
 }
 @Test void unsupportedAttributeAndFiveEntityProtectionDoNotBecomeConfirmedOutputPaths(){
  var go=new WorkerV55IntegrationTest();for(var name:List.of("href","onclick","style","srcdoc"))assertTrue(go.run("res.send(`<p "+name+"=\"${req.query.name}\">x</p>`);").validatedFindings().isEmpty());
  assertTrue(go.run("const safe=req.query.name.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('\"','&quot;').replaceAll(\"'\",'&#x27;');res.send(`<p title=\"${safe}\">x</p>`);").validatedFindings().isEmpty());
 }
}
