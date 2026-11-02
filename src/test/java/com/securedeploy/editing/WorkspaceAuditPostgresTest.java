package com.securedeploy.editing;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/** Independent PostgreSQL failure injection; never accepts an operating datasource. */
@EnabledIfEnvironmentVariable(named="SECUREDEPLOY_RELEASE_PG_TEST",matches="1")
@EnabledIfEnvironmentVariable(named="SECUREDEPLOY_RELEASE_PG_URL",matches="jdbc:postgresql://127\\.0\\.0\\.1:58550/(?:trust02_pgtest|release_cut01_pgtest|accuracy01_pgtest|accuracy02_pgtest|accuracy03_pgtest|accuracy04_pgtest)")
class WorkspaceAuditPostgresTest {
 @Test void commitAndDeletionEvidenceAreAtomicAndReceiptsSurviveSourceExpiry() throws Exception {
  String url=System.getenv("SECUREDEPLOY_RELEASE_PG_URL"),schema="trust02_audit_"+UUID.randomUUID().toString().replace("-","");
  var admin=new JdbcTemplate(new DriverManagerDataSource(url,"ai05_fixture",""));admin.execute("create schema "+schema);
  try {
   var jdbc=new JdbcTemplate(new DriverManagerDataSource(url+"?currentSchema="+schema,"ai05_fixture",""));
   for(String table:List.of("users","projects","reviews")){jdbc.execute("create table "+table+"(id bigint primary key)");jdbc.update("insert into "+table+" values(1)");}
   for(String migration:List.of("V001__encrypted_workspaces.sql","V003__workspace_events.sql","V004__workspace_event_actor.sql"))jdbc.execute(new String(getClass().getResourceAsStream("/db/epic01/"+migration).readAllBytes(),StandardCharsets.UTF_8));
   var mapper=new ObjectMapper().findAndRegisterModules();var vault=new WorkspaceVault(jdbc,mapper,true,Base64.getEncoder().encodeToString(new byte[32]),"test",3600);vault.configureAudit(true);
   Instant created=Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS),expiry=created.plusSeconds(3600);
   byte[] bytes="const SOURCE_NOT_IN_AUDIT = 1;".getBytes(StandardCharsets.UTF_8);String id=UUID.randomUUID().toString(),file=UUID.randomUUID().toString(),request=UUID.randomUUID().toString();
   var f=new WorkspaceVault.File(file,"owned.js",bytes,false,0100644,SourceArchive.hash(bytes),null,"UNCHANGED",List.of());
   var snapshot=new WorkspaceVault.Snapshot(1,id,1,1,1,1,created,expiry,"owned","UNVERIFIED_REUPLOAD",List.of(f),List.of());
   assertEquals(1,vault.put(snapshot,0));
   jdbc.execute("create function audit_failure() returns trigger language plpgsql as $$ begin raise exception 'OWNED_AUDIT_FAILURE'; end $$; create trigger audit_failure before insert on editing_workspace_event_v1 for each row execute function audit_failure();");
   assertThrows(RuntimeException.class,()->vault.put(snapshot,1,new WorkspaceVault.Write(request,file,f.hash(),1L,"SAVED")));
   assertEquals(1,vault.stored(id,1).orElseThrow().version());assertEquals(1,vault.events(id,1).size());assertTrue(vault.receipt(id,1,request).isEmpty());
   jdbc.execute("drop trigger audit_failure on editing_workspace_event_v1");
   assertEquals(2,vault.put(snapshot,1,new WorkspaceVault.Write(request,file,f.hash(),1L,"SAVED")));
   assertTrue(vault.receipt(id,1,request).isPresent());assertTrue(vault.receipt(id,2,request).isEmpty());
   assertEquals(1,vault.cleanup(expiry.plusSeconds(1)));assertEquals(0,vault.cleanup(expiry.plusSeconds(2)));
   assertTrue(vault.stored(id,1).isEmpty());assertTrue(vault.receipt(id,1,request).isPresent());
   assertEquals(1,vault.events(id,1).stream().filter(e->e.type().equals("EXPIRED")).count());
   assertTrue(vault.events(id,1).stream().filter(e->e.type().equals("EXPIRED")).allMatch(e->e.actorType().equals("SYSTEM")&&e.instanceId()!=null));
   assertFalse(mapper.writeValueAsString(vault.events(id,1)).contains("SOURCE_NOT_IN_AUDIT"));
   // Failed audit insertion also rolls back an explicit source deletion.
   assertEquals(1,vault.put(snapshot,0));jdbc.execute("create trigger audit_failure before insert on editing_workspace_event_v1 for each row execute function audit_failure();");
   assertThrows(RuntimeException.class,()->vault.delete(id,1,1));assertTrue(vault.stored(id,1).isPresent());
   assertEquals(0,vault.events(id,1).stream().filter(e->e.type().equals("DELETED")).count());
   jdbc.execute("drop trigger audit_failure on editing_workspace_event_v1");vault.delete(id,1,1);
   assertTrue(vault.events(id,1).stream().filter(e->e.type().equals("DELETED")).allMatch(e->e.actorType().equals("OWNER")&&e.instanceId()!=null));
   assertTrue(vault.stored(id,1).isEmpty());assertEquals(1,vault.events(id,1).stream().filter(e->e.type().equals("DELETED")).count());
  } finally {admin.execute("drop schema "+schema+" cascade");}
 }
}
