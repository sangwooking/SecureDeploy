package com.securedeploy.ai.service;
import com.fasterxml.jackson.databind.*;
import com.securedeploy.ai.config.*;
import com.securedeploy.editing.WorkspacePatch;
import java.lang.reflect.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
/** NEXT-01 test-only: one explicit approved attempt; no production bean or old approval reuse. */
public final class Next01LiveGate {
 static final String MODEL="gpt-5.4-mini-2026-03-17";
 static final Path ROOT=Path.of("/private/tmp/securedeploy-next01-paid-gate");
 static final ObjectMapper JSON=new ObjectMapper();
 static void approved(Path root)throws Exception {
  var a=JSON.readTree(root.resolve("APPROVAL.json").toFile());
  if(!a.path("approved").asBoolean()||!a.path("task").asText().equals("SecureDeploy NEXT-01")||!a.path("model").asText().equals(MODEL)||a.path("maximumAttempts").asInt()!=1||!a.path("budgetUsd").asText().equals("0.05")||a.path("expiresAtEpochSeconds").asLong()<Instant.now().getEpochSecond())throw new IllegalStateException("NEXT01_EXPLICIT_APPROVAL_REQUIRED");
 }
 static void scope(WorkspacePatch.Prompt p,Path root)throws Exception {
  var wire=JSON.readTree(root.resolve("A_PLANNED_REQUEST.json").toFile());var expected=(com.fasterxml.jackson.databind.node.ObjectNode)JSON.readTree(wire.at("/input/0/content").asText());
  var actual=(com.fasterxml.jackson.databind.node.ObjectNode)JSON.readTree(p.untrustedData());
  if(!actual.path("fileId").asText().matches("[0-9a-f-]{36}")||p.untrustedData().getBytes(StandardCharsets.UTF_8).length>8192)throw new IllegalStateException("NEXT01_SCOPE_REJECTED");
  expected.remove("fileId");actual.remove("fileId");
  if(!actual.equals(expected)||!p.instructions().equals(wire.path("instructions").asText())||!p.schema().equals(JSON.convertValue(wire.at("/text/format/schema"),Map.class)))throw new IllegalStateException("NEXT01_SCOPE_REJECTED");
 }
 static synchronized void reserve(Path root,WorkspacePatch.Prompt p)throws Exception {
  approved(root);scope(p,root);
  try(var c=FileChannel.open(root.resolve("attempts.txt"),StandardOpenOption.CREATE,StandardOpenOption.READ,StandardOpenOption.WRITE);var lock=c.lock()){
   if(c.size()!=0)throw new IllegalStateException("NEXT01_SINGLE_ATTEMPT_LIMIT");c.write(ByteBuffer.wrap("1".getBytes(StandardCharsets.UTF_8)));c.force(true);
   Files.writeString(root.resolve("A_ACTUAL_PROMPT.json"),JSON.writeValueAsString(p),StandardOpenOption.CREATE_NEW);
  }
 }
 public static AiProviderResolver create(AiProperties properties,RealOpenAiProvider real)throws Exception {
  approved(ROOT);String key=System.getenv("OPENAI_API_KEY");if(key==null||key.isBlank())throw new IllegalStateException("NEXT01_SERVER_KEY_MISSING");
  properties.setProvider(AiProviderType.OPENAI);properties.getOpenai().setModel(MODEL);properties.getOpenai().setApiKey(key);
  var started=new ThreadLocal<Long>();
  var gate=(AiProvider)Proxy.newProxyInstance(AiProvider.class.getClassLoader(),new Class<?>[]{AiProvider.class},(proxy,method,args)->{
   if(method.getDeclaringClass()==Object.class)return switch(method.getName()){case "toString"->"NEXT01 approved test provider";case "hashCode"->System.identityHashCode(proxy);case "equals"->proxy==args[0];default->null;};
   if(!Set.of("providerType","isAvailable","executionOrigin","consumeLastTokenUsage","generateWorkspacePatch").contains(method.getName()))throw new UnsupportedOperationException("NEXT01_OPERATION_NOT_APPROVED");
   boolean generation=method.getName().equals("generateWorkspacePatch");if(generation){reserve(ROOT,(WorkspacePatch.Prompt)args[0]);started.set(System.nanoTime());}
   try{Object result=method.invoke(real,args);
    if(generation)Files.writeString(ROOT.resolve("A_MODEL_OUTPUT.json"),JSON.writeValueAsString(result),StandardOpenOption.CREATE_NEW);
    if(method.getName().equals("consumeLastTokenUsage")&&started.get()!=null){var record=new LinkedHashMap<String,Object>();record.put("latencyMs",(System.nanoTime()-started.get())/1000000);record.put("usage",((Optional<?>)result).orElse(null));record.put("invoiceAmountKnown",false);Files.writeString(ROOT.resolve("A_USAGE.json"),JSON.writeValueAsString(record));started.remove();}return result;
   }catch(InvocationTargetException e){if(generation)Files.writeString(ROOT.resolve("A_FAILURE.json"),JSON.writeValueAsString(Map.of("errorClass",e.getCause().getClass().getSimpleName(),"invoiceAmountKnown",false)));throw e.getCause();}
  });return new AiProviderResolver(properties,List.of(gate,new TemplateAiProvider()));
 }
}
