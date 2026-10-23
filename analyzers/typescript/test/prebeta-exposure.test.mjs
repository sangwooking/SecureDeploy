import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {prebetaCases,summarizePrebeta} from './prebeta-exposure-cases.mjs';
for(const c of prebetaCases)test('pre-beta exposure contract: '+c.id,()=>{
  const r=analyze(c.input),found=r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');
  assert.equal(found.length>0,c.truth==='RISK');
  if(c.truth==='RISK')for(const f of found){assert.equal(f.disposition,'REVIEW_REQUIRED');assert.equal(f.confidence,'HIGH');assert.ok(f.source.line>0&&f.sink.line>0);}
  if(c.truth==='UNKNOWN')assert.ok(r.exposureUses.some(u=>['FLOW_UNRESOLVED','SENSITIVITY_UNVERIFIED'].includes(u.status))||r.files.some(f=>f.limitations.some(l=>/UNRESOLVED|UNSUPPORTED|UNKNOWN/.test(l))));
  const text=JSON.stringify(r);assert.ok(!text.includes('ghp_'+'b'.repeat(36)));assert.ok(!text.includes('SUPABASE_SERVICE_ROLE_KEY'));
});
test('pre-beta metrics keep unknown separate from successful detection',()=>{
  const report=summarizePrebeta(analyze);assert.equal(report.counts.FP,0);assert.equal(report.counts.FN,0);assert.equal(report.counts.UNKNOWN,5);
  const overconfident=summarizePrebeta(input=>{const r=analyze(input);return {...r,findings:[...r.findings,{ruleId:'TS_SENSITIVE_DATA_EXPOSURE'}]};});
  assert.equal(overconfident.counts.UNEXPECTED_CANDIDATE,5);assert.equal(overconfident.counts.UNKNOWN,0);
});
test('shadowed, mutated and escaped process/response APIs do not establish environment or sending proof',()=>{
 const base="const express=require('express');const app=express();";
 for(const body of ["const process={env:{API_SECRET:'public'}};response.json(process.env.API_SECRET);",
   "process.env.API_SECRET='public';response.json(process.env.API_SECRET);",
   "delete process.env.API_SECRET;response.json(process.env.API_SECRET);",
   "const p=process;response.json(process.env.API_SECRET);",
   "mutate(process.env);response.json(process.env.API_SECRET);",
   "response.json=custom;response.json(process.env.API_SECRET);",
   "response.json(200,process.env.API_SECRET);"]){
  const r=analyze({files:[{filePath:'server.cjs',content:base+"app.get('/',(request,response)=>{"+body+"});"}],nodeManifests:[{filePath:'package.json',express:'4.18.0'}]});
  assert.equal(r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE').length,0,body);
  assert.ok(r.exposureUses.some(u=>u.status==='FLOW_UNRESOLVED')||r.files[0].limitations.some(l=>/UNVERIFIED|UNKNOWN/.test(l)));
 }
});
test('public-looking names outside Next retain uncertainty rather than inventing a private key',()=>{
 for(const key of ['VITE_PUBLIC_API_KEY','NEXT_PUBLIC_API_KEY','SUPABASE_ANON_KEY','SUPABASE_PUBLISHABLE_KEY']){
  const r=analyze({files:[{filePath:'server.cjs',content:`const express=require('express');const app=express();app.get('/',(request,response)=>response.json(process.env.${key}));`}],nodeManifests:[{filePath:'package.json',express:'4.18.0'}]});
  assert.equal(r.findings.length,0);assert.ok(r.exposureUses.some(u=>u.status==='SENSITIVITY_UNVERIFIED'));
 }
});
test('environment existence checks are not mutations and cannot hide a later response value',()=>{
 const r=analyze({files:[{filePath:'server.cjs',content:"const express=require('express');const app=express();app.get('/',(request,response)=>{const configured=!!process.env.API_SECRET;response.json({configured,value:process.env.API_SECRET});});"}],nodeManifests:[{filePath:'package.json',express:'4.18.0'}]});
 assert.equal(r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE').length,1);
});
test('deleted, escaped and aliased console implementations remain unverified',()=>{
 for(const prefix of ['delete console.log;','Object.assign(console,custom);','const logger=console;']){
  const r=analyze({files:[{filePath:'supabase/functions/check/index.ts',content:prefix+"Deno.serve(request=>{console.log(Deno.env.get('API_SECRET'));return new Response('ok');});"}]});
  assert.equal(r.findings.length,0);assert.ok(r.exposureUses.some(u=>u.status==='FLOW_UNRESOLVED'));
 }
});
test('visible JSON replacer configuration is uncertainty, not proof of leakage or of safe masking',()=>{
 const r=analyze({files:[{filePath:'server.cjs',content:"const express=require('express');const app=express();app.set('json replacer',(key,value)=>key==='secret'?undefined:value);app.get('/',(request,response)=>response.json({secret:process.env.API_SECRET}));"}],nodeManifests:[{filePath:'package.json',express:'4.18.0'}]});
 assert.equal(r.findings.length,0);assert.ok(r.exposureUses.some(u=>u.status==='FLOW_UNRESOLVED'));
 assert.ok(r.files[0].limitations.includes('EXPRESS_JSON_REPLACER_CONTEXT_UNVERIFIED'));
});
