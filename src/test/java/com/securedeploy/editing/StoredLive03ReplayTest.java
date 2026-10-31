package com.securedeploy.editing;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
/** Historical response replay only: no provider, key, transport or new model call. */
class StoredLive03ReplayTest {
 @ParameterizedTest @ValueSource(strings={"A","B"})
 void historicalRealPlanStillValidatesButMissingOrInventedFieldCannotApply(String name)throws Exception {
  var json=new ObjectMapper().findAndRegisterModules();
  try(var v=getClass().getResourceAsStream("/epic01/live03/"+name+"_PREPARED_VIEW.json");var p=getClass().getResourceAsStream("/epic01/live03/"+name+"_MODEL_PLAN.json")){
   var raw=(com.fasterxml.jackson.databind.node.ObjectNode)json.readTree(v);var recordedHash=raw.remove("contextHash");var recordedPlan=raw.remove("plan");
   var view=json.treeToValue(raw,WorkspacePatch.View.class);
   assertEquals(recordedHash.asText(),view.contextHash());assertEquals(recordedPlan,json.readTree(json.writeValueAsBytes(view.plan())));
   var plan=WorkspacePatchPlan.parse(json.readTree(p));
   assertEquals(name.equals("A")?2:3,plan.operations().size());assertEquals("OPENAI",view.provider().origin());
   assertDoesNotThrow(()->WorkspacePatchPlan.validate(plan,view));
   var partial=new WorkspacePatchPlan.Output(plan.decision(),plan.objectId(),plan.operations().subList(1,plan.operations().size()),plan.explanation(),plan.verificationSteps(),plan.limitations());
   assertThrows(IllegalArgumentException.class,()->WorkspacePatchPlan.validate(partial,view));
   var wrong=new WorkspacePatchPlan.Output(plan.decision(),plan.objectId(),List.of(new WorkspacePatchPlan.Operation("invented",WorkspacePatchPlan.OPERATION)),plan.explanation(),plan.verificationSteps(),plan.limitations());
   assertThrows(IllegalArgumentException.class,()->WorkspacePatchPlan.validate(wrong,view));
  }
 }
}
