import{test}from'node:test';import assert from'node:assert/strict';import{analyze,evaluateStaticRoutes,VERSION}from'../analyzer.mjs';
import{staticRouteCases}from'./static-route-fixtures.mjs';
import{execFileSync}from'node:child_process';import{fileURLToPath}from'node:url';
for(const c of staticRouteCases)test(`evaluation-only static route: ${c.id}`,()=>{
 const before=analyze(c.input),r=evaluateStaticRoutes(c.input);
 assert.equal(r.engineVersion,VERSION);assert.equal(r.riskApplied,false);assert.deepEqual(r.finalUserFindings,[]);
 const matched=r.rows.filter(x=>x.category===c.category);
 if(c.category==='NONE')assert.equal(r.rows.filter(x=>['A','B','C','D'].includes(x.category)).length,0,c.id);
 else assert.ok(matched.length,c.id);
 assert.equal(r.observations.findings.length,c.findings,c.id);
 assert.ok(r.observations.findings.every(f=>f.confidence!=='HIGH'));
 assert.deepEqual(analyze(c.input),before,'prototype must not affect production');
 assert.deepEqual(evaluateStaticRoutes(c.input),r,'repeat deterministic');
});
test('one handler at two independent registrations retains both evidence associations',()=>{
 const r=evaluateStaticRoutes(staticRouteCases.find(c=>c.id==='shared-handler').input);
 assert.equal(r.rows.length,2);assert.ok(r.rows.every(c=>c.observationRefs.findings.length===1));
 assert.equal(r.observations.findings.length,1,'not two independent vulnerabilities');
});
test('multiple receiver instances at one callsite do not merge connected and unmounted routes',()=>{
 const r=evaluateStaticRoutes({files:[{filePath:'entry.cjs',content:`const express=require('express');const app=express();const a=express.Router(),b=express.Router();
 function register(router,handler){router.post('/',handler);}const handler=(req,res)=>eval(req.body.code);register(a,handler);register(b,handler);app.use('/api',a);`}]});
 assert.equal(r.observations.findings.length,0);assert.ok(r.rows.some(x=>x.traceStatus==='MULTIPLE_REGISTRATION_INSTANCES_UNVERIFIED'));
});
test('factory local state is never initialized merely to resolve a handler or receiver',()=>{
 const c=staticRouteCases.find(c=>c.id==='local-factory-router');const r=evaluateStaticRoutes(c.input);
 assert.ok(r.rows.some(x=>x.category==='E'&&x.traceStatus==='FACTORY_LOCAL_RECEIVER_NOT_CREATED'));
 assert.equal(r.observations.findings.length,0);
});
test('JSON flags and ordinary overrides cannot activate candidate analysis',()=>{
 const c=staticRouteCases[0],r=analyze({...c.input,routeCandidates:true,evaluationOnly:true},{routeCandidates:true,evaluationOnly:true});
 assert.deepEqual(r,analyze(c.input));assert.equal(r.candidates,undefined);assert.equal(r.findings.length,0);
 const out=execFileSync(process.execPath,['--max-old-space-size=192',fileURLToPath(new URL('../worker.mjs',import.meta.url))],{
  input:JSON.stringify({...c.input,routeCandidates:true,evaluationOnly:true}),timeout:10000,maxBuffer:2000000});
 assert.deepEqual(JSON.parse(out),analyze(c.input));
});
test('candidate limits and ordinary execution budgets remain bounded and incomplete',()=>{
 const c=staticRouteCases[0],r=evaluateStaticRoutes(c.input,{maxSteps:35});assert.equal(r.observations.findings.length,0);
 assert.ok(r.files.some(f=>f.limitations.length));
 const many=evaluateStaticRoutes({files:[{filePath:'many.cjs',content:`const r=require('express').Router();`+Array.from({length:24},(_,i)=>`r.post('/${i}',(req,res)=>eval(req.body.code));`).join('')}]});
 assert.ok(many.rows.filter(x=>x.traceStatus==='STATIC_ROUTE_FLOW_LIMIT').length>=4);
 assert.ok(Object.values(many.observations).reduce((n,x)=>n+x.length,0)<=200);
});
test('prior same-path handlers and unknown factory middleware do not become new request sources',()=>{
 for(const source of [
  `const r=require('express').Router();r.post('/',(req,res)=>res.end());r.post('/',(req,res)=>eval(req.body.code));`,
  `const r=require('express').Router();module.exports=()=>{r.use(external);r.post('/',(req,res)=>eval(req.body.code));};`,
  `const r=require('express').Router();module.exports=()=>{external(r);r.post('/',(req,res)=>eval(req.body.code));};`,
  `const r=require('express').Router();module.exports=()=>{r.post=external;r.post('/',(req,res)=>eval(req.body.code));};`
 ]){
  const r=evaluateStaticRoutes({files:[{filePath:'routes.cjs',content:source}]});assert.equal(r.observations.findings.length,0);
  assert.ok(r.rows.some(x=>/UNKNOWN/.test(x.traceStatus)));
 }
});
