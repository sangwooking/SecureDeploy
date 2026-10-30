package com.securedeploy.ai.service;
import com.fasterxml.jackson.databind.*;
import com.securedeploy.editing.WorkspacePatch;
import java.nio.file.*;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class Next01LiveGateTest {
 @TempDir Path root;final ObjectMapper json=new ObjectMapper();
 WorkspacePatch.Prompt setup()throws Exception {try(var in=getClass().getResourceAsStream("/next01/A_PLANNED_REQUEST.json")){var wire=json.readTree(in);Files.writeString(root.resolve("A_PLANNED_REQUEST.json"),wire.toString());return new WorkspacePatch.Prompt(wire.path("instructions").asText(),wire.at("/input/0/content").asText(),json.convertValue(wire.at("/text/format/schema"),Map.class));}}
 void approve(String task)throws Exception {Files.writeString(root.resolve("APPROVAL.json"),json.writeValueAsString(Map.of("approved",true,"task",task,"model",Next01LiveGate.MODEL,"maximumAttempts",1,"budgetUsd","0.05","expiresAtEpochSeconds",Instant.now().plusSeconds(300).getEpochSecond())));}
 @Test void noApprovalOrOldApprovalNeverReservesAnAttempt()throws Exception {var p=setup();assertThrows(Exception.class,()->Next01LiveGate.reserve(root,p));approve("SecureDeploy TEST-01");assertThrows(Exception.class,()->Next01LiveGate.reserve(root,p));assertFalse(Files.exists(root.resolve("attempts.txt")));}
 @Test void oneAttemptIsPersistedBeforeTransportAndNeverRetried()throws Exception {var p=setup();approve("SecureDeploy NEXT-01");Next01LiveGate.reserve(root,p);assertEquals("1",Files.readString(root.resolve("attempts.txt")));assertThrows(Exception.class,()->Next01LiveGate.reserve(root,p));assertEquals("1",Files.readString(root.resolve("attempts.txt")));}
 @Test void alteredCodeOrContextCannotReservePaidScope()throws Exception {var p=setup();approve("SecureDeploy NEXT-01");var changed=new WorkspacePatch.Prompt(p.instructions(),p.untrustedData().replace("count: 12","count: 99"),p.schema());assertThrows(Exception.class,()->Next01LiveGate.reserve(root,changed));assertFalse(Files.exists(root.resolve("attempts.txt")));}
}
