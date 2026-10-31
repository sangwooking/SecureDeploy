package com.securedeploy.ai.usage;

import static org.junit.jupiter.api.Assertions.*;
import java.math.BigDecimal;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@EnabledIfEnvironmentVariable(named="SECUREDEPLOY_RELEASE_PG_TEST",matches="1")
class ReleaseLedgerPostgresTest {
 JdbcTemplate db;long user,project;
 @BeforeEach void setup(){
  String url=System.getenv().getOrDefault("SECUREDEPLOY_RELEASE_PG_URL","jdbc:postgresql://127.0.0.1:58057/release_gate01");
  if(!Set.of("jdbc:postgresql://127.0.0.1:58057/release_gate01","jdbc:postgresql://127.0.0.1:58220/ready02_fixture","jdbc:postgresql://127.0.0.1:58450/v53_fixture","jdbc:postgresql://127.0.0.1:58550/v53_gate_fixture","jdbc:postgresql://127.0.0.1:58550/source01_pgtest","jdbc:postgresql://127.0.0.1:58550/source02_pgtest","jdbc:postgresql://127.0.0.1:58550/sca03_pgtest","jdbc:postgresql://127.0.0.1:58550/v54_pgtest").contains(url))throw new IllegalStateException("ISOLATED_DB_REQUIRED");
  db=new JdbcTemplate(new DriverManagerDataSource(url,"ai05_fixture",""));
  var row=db.queryForMap("select user_id,id from projects where user_id is not null order by id limit 1");
  user=((Number)row.get("user_id")).longValue();project=((Number)row.get("id")).longValue();db.update("delete from ai_usage_request_v1");
 }
 DurableAiLedger ledger(String u,String p,String g){return new DurableAiLedger(db,true,new BigDecimal(u),new BigDecimal(p),new BigDecimal(g));}
 AiAdmission.Request request(String id){return new AiAdmission.Request(user,project,id,"workspace_patch_plan_v1","a".repeat(64),"gpt-5.4-mini-2026-03-17",AiAdmission.hash("i\0d"));}
 String reserve(DurableAiLedger l,String id){return l.reserve(request(id),"workspace_patch_plan_v1","gpt-5.4-mini-2026-03-17",AiAdmission.hash("i\0d"),32768,2000);}
 @Test void concurrentInstancesShareDuplicateAndServiceBudget()throws Exception{
  var a=ledger("1","1","0.068");var b=ledger("1","1","0.068");var pool=Executors.newFixedThreadPool(8);
  try{
   List<Callable<Boolean>> jobs=new ArrayList<>();for(int i=0;i<8;i++){final int n=i;jobs.add(()->{try{reserve(n%2==0?a:b,"same-id");return true;}catch(RuntimeException denied){return false;}});}
   int successes=0;for(var f:pool.invokeAll(jobs))if(f.get())successes++;assertEquals(1,successes);
   reserve(b,"second-id");assertThrows(RuntimeException.class,()->reserve(a,"third-id"));
   assertEquals(2,db.queryForObject("select count(*) from ai_usage_request_v1 where state='RESERVED'",Integer.class));
   assertEquals("PRE_SEND_FAILED",db.queryForObject("select state from ai_usage_request_v1 where request_id='third-id'",String.class));
  }finally{pool.shutdownNow();}
 }
 @Test void separateUserAndProjectLimitsAndConsentPayloadModelGate(){
  reserve(ledger("0.04","1","1"),"one");assertThrows(RuntimeException.class,()->reserve(ledger("0.04","1","1"),"two"));
  db.update("delete from ai_usage_request_v1");reserve(ledger("1","0.04","1"),"one");assertThrows(RuntimeException.class,()->reserve(ledger("1","0.04","1"),"two"));
  var l=ledger("1","1","1");assertThrows(RuntimeException.class,()->l.reserve(null,"x","x","x",10,10));
  assertThrows(RuntimeException.class,()->l.reserve(request("bad"),"semantic_review",request("bad").model(),request("bad").transmissionHash(),10,10));
  assertThrows(RuntimeException.class,()->l.reserve(request("bad"),"workspace_patch_plan_v1",request("bad").model(),"b".repeat(64),10,10));
 }
 @Test void restartRetainsUncertainReservationsAndNeverRetries(){
  var first=ledger("1","1","1");reserve(first,"interrupted");first.sending("interrupted");
  db.update("update ai_usage_request_v1 set updated_at=current_timestamp-interval '10 minutes'");
  var next=ledger("1","1","1");assertEquals(1,next.reconcile());assertThrows(RuntimeException.class,()->reserve(next,"interrupted"));
  assertEquals("PROVIDER_UNKNOWN",db.queryForObject("select state from ai_usage_request_v1",String.class));
  assertTrue(db.queryForObject("select reserved_usd from ai_usage_request_v1",BigDecimal.class).signum()>0);
 }
 @Test void completionUsageUnknownAndPostResponseDatabaseFailure(){
  var l=ledger("1","1","1");reserve(l,"known");l.sending("known");l.complete("known",new AiTokenUsage(31,7,38,true,0,"gpt-5.4-mini-2026-03-17",true));
  assertEquals("COMPLETED",db.queryForObject("select state from ai_usage_request_v1 where request_id='known'",String.class));
  reserve(l,"unknown");l.sending("unknown");l.complete("unknown",new AiTokenUsage(0,0,0,true));
  assertEquals("REVIEW_REQUIRED",db.queryForObject("select state from ai_usage_request_v1 where request_id='unknown'",String.class));
  reserve(l,"settlement-failure");l.sending("settlement-failure");
  db.execute("create function release_fail_settlement() returns trigger language plpgsql as $$ begin if NEW.state='COMPLETED' then raise exception 'controlled settlement failure'; end if; return NEW; end $$");
  db.execute("create trigger release_settlement_failure before update on ai_usage_request_v1 for each row execute function release_fail_settlement()");
  try{assertThrows(RuntimeException.class,()->l.complete("settlement-failure",new AiTokenUsage(1,1,2,true,0,"gpt-5.4-mini-2026-03-17",true)));l.uncertain("settlement-failure");
   assertEquals("PROVIDER_UNKNOWN",db.queryForObject("select state from ai_usage_request_v1 where request_id='settlement-failure'",String.class));
  }finally{db.execute("drop trigger release_settlement_failure on ai_usage_request_v1");db.execute("drop function release_fail_settlement()");}
 }
}
