import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {rate28Cases} from './rate28-cases.mjs';
const rule='JS_RATE_LIMIT_BYPASS_REVIEW';
const tp=new Set(['always-skip','next-handler','changed-before']);
for(const c of rate28Cases)test('rate28 frozen control '+c.id,()=>{
 const r=analyze(c.input);assert.deepEqual(r,analyze(c.input));
 assert.equal(r.findings.filter(f=>f.ruleId===rule).length,tp.has(c.id)?1:0);
 if(c.id==='zero-blocks')assert.ok(r.nodeUses.some(u=>u.kind==='RATE_LIMIT_ZERO_BLOCKS_BOUND'));
 if(c.id.startsWith('upstash'))assert.ok(r.files.some(f=>f.limitations.includes('UPSTASH_RATE_LIMIT_EXECUTION_CONTRACT_NOT_SUPPORTED')));
});
const packet=options=>{
 const input=structuredClone(rate28Cases[0].input);
 input.files[0].content=input.files[0].content.replace('{limit:3,skip:()=>true}',options);return input;
};
const hits=input=>analyze(input).findings.filter(f=>f.ruleId===rule);
test('callback return semantics, generator and async bodies are not guessed',()=>{
 for(const options of ['{skip:()=>{true;}}','{skip:function*(){return false;}}','{skip:async()=>true}',
  '{skip:()=>{external();return true;}}','{handler:(req,res,next)=>{const later=next;later();}}',
  '{keyGenerator:()=>{ "key"; },skip:()=>true}', '{store:external,skip:()=>true}',
  '{limit:-1,skip:()=>true}', '{windowMs:0,skip:()=>true}'])assert.equal(hits(packet(options)).length,0,options);
 assert.equal(hits(packet('{skip:()=>{return true;}}')).length,1);
 assert.equal(hits(packet('{handler:(a,b,c)=>{c();}}')).length,1);
});
test('normal bounded contract never certifies proxy, identity, distributed store or business budget',()=>{
 const r=analyze(packet('{limit:3}'));
 const observation=r.nodeUses.find(u=>u.kind==='RATE_LIMIT_DEFAULT_STOP_BOUND');assert.ok(observation);
 for(const s of ['IP_DECLARED_PROXY_UNKNOWN','MEMORY_STORE_PROCESS_LOCAL_DECLARATION','RATE_BUDGET_BUSINESS_REQUIREMENTS_UNKNOWN',
  'STORE_CONNECTIVITY_AND_MULTI_INSTANCE_EFFECT_UNKNOWN','AUTHENTICATION_AND_DISTRIBUTED_ABUSE_NOT_PROVEN'])assert.ok(observation.limitations.includes(s));
 assert.equal(hits(packet('{limit:3}')).length,0);
});
test('unsupported source, no observed work, overwritten native and ambiguous mount fail closed',()=>{
 for(const modify of [
  s=>s.replace("const rateLimit=require('express-rate-limit');","const rateLimit=external;"),
  s=>s.replace("fs.writeFileSync('/owned/state',req.body.value);",'externalWork(req);'),
  s=>s.replace('app.use(rateLimit(',"app.use('/other',rateLimit("),
  s=>s.replace('app.use(rateLimit(',"const original=rateLimit;rateLimit.default=external;app.use(original("),
  s=>s.replace("fs.writeFileSync('/owned/state',req.body.value)","fs.writeFileSync()"),
 ]){const p=packet('{skip:()=>true}');p.files[0].content=modify(p.files[0].content);assert.equal(hits(p).length,0);}
 const p=packet('{skip:()=>true}');p.nodeManifests[0]['express-rate-limit']='^7.5.0';assert.equal(hits(p).length,0);
 assert.equal(analyze(packet('{skip:()=>true}'),{maxSteps:2}).findings.length,0);
});
test('module options aliases and entry-local changes do not leak between requests',()=>{
 const base=packet('{skip:()=>true}');const body=base.files[0].content;
 const other="app.post('/other',(req,res)=>{rateLimit.default=external;res.end('ok');});";
 for(const text of [body+other,body.replace("app.post('/work'",other+"app.post('/work'")]){
  const p=structuredClone(base);p.files[0].content=text;assert.equal(hits(p).length,1);
 }
 const r=analyze(base);const encoded=JSON.stringify(r);assert.ok(!encoded.includes('node_modules'));
 assert.ok(r.findings.find(f=>f.ruleId===rule).flow.some(l=>l.kind==='RATE_LIMIT_REQUEST_REGISTRATION'));
});
test('bounded corrections remove only the explicit failure and retain the work source',()=>{
 for(const [before,after]of [['{limit:3,skip:()=>true}','{limit:3,skip:()=>false}'],
  ['{limit:3,handler:(req,res,next)=>next()}','{limit:3}']]){
  assert.equal(hits(packet(before)).length,1);const input=packet(after);assert.equal(hits(input).length,0);
  const r=analyze(input);assert.ok(r.nodeUses.some(u=>u.kind==='RATE_LIMIT_DEFAULT_STOP_BOUND'));
  assert.ok(r.resourceUses.some(u=>u.location.kind==='NODE_FILE_WRITE'&&u.executionObserved));
 }
});
test('nested Router policy inheritance is unknown, not a claimed absence or completed protection',()=>{
 const p=packet('{limit:3,skip:()=>true}');p.files[0].content=p.files[0].content.replace("app.post('/work'","const router=require('express').Router();app.use('/api',router);router.post('/work'");
 const r=analyze(p);assert.equal(hits(p).length,0);
 assert.ok(r.nodeUses.some(u=>u.kind==='RATE_LIMIT_APPLICATION_UNKNOWN'));
 assert.ok(!r.nodeUses.some(u=>u.kind==='RATE_LIMIT_DEFAULT_STOP_BOUND'));
});
test('earlier overlapping routes and case or trailing-slash mount ambiguity do not prove dispatch',()=>{
 for(const transform of [
  s=>s.replace("app.post('/work'","app.post('/work',(req,res)=>res.end('first'));app.post('/work'"),
  s=>s.replace('app.use(rateLimit(',"app.use('/WORK',rateLimit("),
  s=>s.replace('app.use(rateLimit(',"app.use('/work/',rateLimit("),
 ]){const p=packet('{skip:()=>true}');p.files[0].content=transform(p.files[0].content);const r=analyze(p);
  assert.equal(hits(p).length,0);assert.ok(r.nodeUses.some(u=>u.kind==='RATE_LIMIT_APPLICATION_UNKNOWN'));
 }
});
test('relative policy module preserves provenance and work locations without executing its code',()=>{
 const p=packet('{limit:3,skip:()=>true}');
 p.files[0].content=p.files[0].content.replace("const rateLimit=require('express-rate-limit');","const policy=require('./policy.cjs');")
  .replace('app.use(rateLimit({limit:3,skip:()=>true}));','app.use(policy);');
 p.files.push({filePath:'policy.cjs',content:"const {rateLimit}=require('express-rate-limit');module.exports=rateLimit({limit:3,skip:()=>true});"});
 const f=hits(p);assert.equal(f.length,1);assert.equal(f[0].source.filePath,'policy.cjs');assert.equal(f[0].sink.filePath,'server.cjs');
});
test('correct Upstash success exit is deferred, never silently counted as supported protection',()=>{
 const p=structuredClone(rate28Cases.find(c=>c.id==='upstash-ignored').input);
 p.files[0].content=p.files[0].content.replace("await limiter.limit('owned');","const result=await limiter.limit('owned');if(!result.success)return new Response('blocked',{status:429});");
 const r=analyze(p);assert.equal(hits(p).length,0);
 assert.ok(r.files.some(f=>f.limitations.includes('UPSTASH_RATE_LIMIT_EXECUTION_CONTRACT_NOT_SUPPORTED')));
 assert.ok(!r.nodeUses.some(u=>u.kind==='RATE_LIMIT_DEFAULT_STOP_BOUND'));
});
