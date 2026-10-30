package com.securedeploy.editing;
import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
class PatchCallPolicyTest {
 final WorkspacePatch.Prompt prompt=new WorkspacePatch.Prompt("trusted server policy","synthetic data",Map.of());
 final String model="gpt-5.4-mini-2026-03-17";
 String hash(int n){return SourceArchive.hash(("context-"+n).getBytes(java.nio.charset.StandardCharsets.UTF_8));}
 @Test void defaultOffAndUnknownOriginOrModelCannotReservePaidCalls(){
  var policy=new PatchCallPolicy(false);assertThrows(RuntimeException.class,()->policy.reserve(1,1,hash(1),model,"OPENAI",prompt));
  assertThrows(RuntimeException.class,()->policy.reserve(1,1,hash(1),model,"UNVERIFIED_PROVIDER",prompt));
  assertThrows(RuntimeException.class,()->new PatchCallPolicy(true).reserve(1,1,hash(1),"unknown-model","OPENAI",prompt));
 }
 @Test void concurrencyDuplicateAndFailedUsageRemainReserved(){
  var p=new PatchCallPolicy(true);var a=p.reserve(1,1,hash(1),model,"OPENAI",prompt);var b=p.reserve(2,1,hash(2),model,"OPENAI",prompt);
  assertThrows(RuntimeException.class,()->p.reserve(3,1,hash(3),model,"OPENAI",prompt));
  a.close();a.close();assertThrows(RuntimeException.class,()->p.reserve(1,1,hash(1),model,"OPENAI",prompt));
  try(var c=p.reserve(3,1,hash(3),model,"OPENAI",prompt)){}b.close();
  try(var c=p.reserve(1,1,hash(4),model,"OPENAI",prompt)){}
  assertThrows(RuntimeException.class,()->p.reserve(1,2,hash(5),model,"OPENAI",prompt)); // user conservative daily budget
 }
 @Test void projectBudgetSpansUsersAndHourlyMockQuotaIsNotLiveSuccess(){
  var p=new PatchCallPolicy(true);for(int i=1;i<=5;i++)try(var c=p.reserve(i,1,hash(i),model,"OPENAI",prompt)){}
  assertThrows(RuntimeException.class,()->p.reserve(6,1,hash(6),model,"OPENAI",prompt));
  var mock=new PatchCallPolicy(false);for(int i=1;i<=6;i++)try(var c=mock.reserve(1,2,hash(i),"mock","MOCK",prompt)){}
  assertThrows(RuntimeException.class,()->mock.reserve(1,2,hash(7),"mock","MOCK",prompt));
 }
 @Test void oversizeAndMalformedContextsNeverConsumeAnAdmissibleCall(){
  var p=new PatchCallPolicy(true);assertThrows(RuntimeException.class,()->p.reserve(1,1,"bad",model,"OPENAI",prompt));
  var big=new WorkspacePatch.Prompt("x".repeat(28001),"",Map.of());assertThrows(RuntimeException.class,()->p.reserve(1,1,hash(1),model,"OPENAI",big));
  try(var c=p.reserve(1,1,hash(1),model,"OPENAI",prompt)){}
 }
 @Test void budgetAndDedupAreProcessScopedWithExplicitClockWindow(){
  var now=new AtomicReference<>(Instant.parse("2026-10-31T00:00:00Z"));var clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now.get();}};
  var p=new PatchCallPolicy(true,clock);try(var c=p.reserve(1,1,hash(1),model,"OPENAI",prompt)){}
  assertThrows(RuntimeException.class,()->p.reserve(1,1,hash(1),model,"OPENAI",prompt));now.set(now.get().plusSeconds(86401));try(var c=p.reserve(1,1,hash(1),model,"OPENAI",prompt)){}
 }
}
