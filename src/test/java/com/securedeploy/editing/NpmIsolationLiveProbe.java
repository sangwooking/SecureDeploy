package com.securedeploy.editing;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.mock.env.MockEnvironment;
/** Explicit manual evaluation entry. Never called by the product or normal tests. */
public class NpmIsolationLiveProbe {
 public static void main(String[] args)throws Exception {
  if(args.length!=3||!NpmIsolationRunner.validImage(args[0]))throw new IllegalArgumentException("PINNED_IMAGE_REQUIRED");
  var json=new ObjectMapper();var env=new MockEnvironment().withProperty("securedeploy.editing.npm-isolation.enabled","true").withProperty("securedeploy.editing.npm-isolation.image",args[0]);
  var runner=new NpmIsolationRunner(json,new NpmRegistry(json),env);if(!runner.available())throw new IllegalStateException("ISOLATION_UNAVAILABLE");
  String name="securedeploy-npm-"+UUID.randomUUID();
  try{
   String code="import fs from 'node:fs';import{spawn}from'node:child_process';const result={uid:process.getuid(),hostCanaryVisible:fs.existsSync("+json.writeValueAsString(args[1])+"),socketVisible:fs.existsSync('/var/run/docker.sock'),secretForwarded:['OPENAI_API_KEY','DB_PASSWORD','JWT_SECRET'].some(k=>process.env[k]),cgroup:{memory:fs.readFileSync('/sys/fs/cgroup/memory.max','utf8').trim(),pids:fs.readFileSync('/sys/fs/cgroup/pids.max','utf8').trim(),cpu:fs.readFileSync('/sys/fs/cgroup/cpu.max','utf8').trim()}};try{fs.writeFileSync('/owned-write','x');result.rootReadonly=false;}catch(e){result.rootReadonly=e.code==='EROFS';}try{for(let i=0;i<4;i++)fs.writeFileSync('/work/owned-quota-'+i,Buffer.alloc(6*1024*1024));result.diskLimited=false;}catch(e){result.diskLimited=e.code==='ENOSPC';}const children=[];let denied=0;for(let i=0;i<40;i++){try{const child=spawn('/bin/sleep',['5'],{stdio:'ignore'});child.on('error',()=>denied++);children.push(child);}catch{denied++;}}await new Promise(r=>setTimeout(r,200));for(const c of children)c.kill('SIGKILL');await new Promise(r=>setTimeout(r,300));result.boundedProcessDenials=denied;result.network=await Promise.all(['http://127.0.0.1:58681/owned','http://169.254.169.254/owned','https://registry.npmjs.org/'].map(async url=>{try{await fetch(url,{signal:AbortSignal.timeout(1000)});return {target:url,reached:true};}catch{return {target:url,reached:false};}}));console.log(JSON.stringify(result));";
   var result=json.readTree(runner.run(runner.containerArgs(name,code),null,8,8192));
   Files.writeString(Path.of(args[2]+".partial"),json.writeValueAsString(result));
   if(result.path("uid").asInt()!=65532||result.path("hostCanaryVisible").asBoolean()||result.path("socketVisible").asBoolean()||result.path("secretForwarded").asBoolean()||!result.path("rootReadonly").asBoolean()||!result.path("diskLimited").asBoolean()||result.path("boundedProcessDenials").asInt()==0)throw new IllegalStateException("BOUNDARY_FAILED");
   for(var row:result.path("network"))if(row.path("reached").asBoolean())throw new IllegalStateException("NETWORK_REACHED");
   // A timed out CLI must be followed by named-container cleanup, not a host fallback.
   runner.cleanup(name);name="securedeploy-npm-"+UUID.randomUUID();boolean timeout=false;
   try{runner.run(runner.containerArgs(name,"await new Promise(r=>setTimeout(r,10000));"),null,1,1024);}catch(IllegalStateException expected){timeout=expected.getMessage().equals("NPM_ISOLATION_TIMEOUT");}
   if(!timeout)throw new IllegalStateException("TIMEOUT_NOT_ENFORCED");runner.cleanup(name);
   String install="node -e \"require('fs').writeFileSync('/work/owned-hook','OWNED')\"";
   byte[] manifest=json.writeValueAsBytes(Map.of("name","owned-isolation-canary","version","1.0.0","scripts",Map.of("install",install)));
   byte[] lock=json.writeValueAsBytes(Map.of("name","owned-isolation-canary","version","1.0.0","lockfileVersion",3,"requires",true,"packages",Map.of("",Map.of("name","owned-isolation-canary","version","1.0.0"))));
   var generated=runner.generate(manifest,lock);if(!json.readTree(generated.manifest()).path("scripts").path("install").asText().equals(install))throw new IllegalStateException("SCRIPT_DATA_CHANGED");
   name="securedeploy-npm-"+UUID.randomUUID();
   String positive="import fs from 'node:fs';import{spawnSync}from'node:child_process';fs.writeFileSync('/work/package.json',"+json.writeValueAsString(new String(manifest,StandardCharsets.UTF_8))+");const child=spawnSync('/usr/local/bin/node',['/usr/local/lib/node_modules/npm/bin/npm-cli.js','install','--offline','--no-audit','--no-fund','--cache=/cache'],{cwd:'/work',env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp'},stdio:'ignore'});console.log(JSON.stringify({ran:child.status===0&&fs.existsSync('/work/owned-hook')}));";
   if(!json.readTree(runner.run(runner.containerArgs(name,positive),null,15,1024)).path("ran").asBoolean())throw new IllegalStateException("OWNED_POSITIVE_CONTROL_FAILED");runner.cleanup(name);
   var report=json.createObjectNode().put("passed",true).put("image",args[0]).put("timeoutAndCleanup",true).put("noHostMounts",true).put("noPackageScriptsExecuted",true).put("ownedHookBlockedByGenerator",true).put("ownedHookPositiveControlRanInsideContainer",true);report.set("actualGuest",result);Files.writeString(Path.of(args[2]),json.writerWithDefaultPrettyPrinter().writeValueAsString(report));System.out.println("OS_ISOLATION_BOUNDARIES_PASSED");
  }finally{runner.cleanup(name);runner.close();}
 }
}
