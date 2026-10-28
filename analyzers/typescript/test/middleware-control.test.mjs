import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {middlewareCases,input} from './middleware-control-fixtures.mjs';

const findings=r=>r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
const proof=r=>r.nodeUses.filter(u=>u.kind==='ROUTE_HANDLER_NOT_REACHED');
for(const c of middlewareCases)test(`bounded route control: ${c.id}`,()=>{
  const r=analyze(input(c)),warnings=findings(r);
  assert.equal(warnings.length,['BLOCKED','NO_ENTRY'].includes(c.truth)?0:1,c.id);
  for(const f of warnings){assert.equal(f.confidence,'HIGH');assert.equal(f.disposition,'REVIEW_REQUIRED');assert.equal(f.source.kind,'EXPRESS_BODY');}
  if(c.truth==='BLOCKED'){
    assert.ok(proof(r).length);
    assert.ok(proof(r)[0].trace.some(p=>[c.exit??'RESPONSE_END'].includes(p.kind)));
    assert.equal(r.files[0].flowStatus,'PARTIAL');
    assert.ok(r.files[0].entrypoints>0);
  }
  if(c.id.startsWith('other-')||c.id==='unrelated-global-route')assert.equal(warnings[0].sink.line,2);
  if(c.truth==='UNKNOWN_RETAIN')assert.equal(proof(r).length,0);
});

test('response completion never stops the remaining statements of the same JavaScript function',()=>{
  for(const method of ['end()','send("closed")','json({ok:true})','sendStatus(403)']){
    const r=analyze({files:[{filePath:'server.js',content:`const app=require('express')();app.post('/',(req,res)=>{res.${method};eval(req.body.value);});`}]});
    assert.equal(findings(r).length,1);assert.equal(proof(r).length,0);
  }
});

test('unsupported response overloads, shadows and mutation do not become termination proof',()=>{
  for(const guard of [
    `(req,res,next)=>res.end({invalid:true})`,
    `(req,res,next)=>res.send(-1)`,
    `(req,res,next)=>res.sendStatus(99)`,
    `(req,res,next)=>res.status(external).json({error:true})`,
    `(req,res,next=external)=>res.end()`,
    `(req,res,next)=>{const end=res.end;end();}`,
    `(req,res,next)=>{let res=other;return res.end();}`,
    `(req,res,next)=>{if(check(req,next))return res.end();else return res.end();}`,
    `(req,res,next)=>{res.end();next=external;next();}`,
  ]){
    const r=analyze({files:[{filePath:'server.js',content:`const app=require('express')();app.post('/',${guard},(req,res)=>eval(req.body.value));`}]});
    assert.equal(findings(r).length,1,guard);assert.equal(proof(r).length,0,guard);
  }
});

test('unknown mount scope, multiple parents and cycles cannot claim local chain protection',()=>{
  for(const setup of [
    `const other=express();app.use('/safe',router);other.use(external);other.use('/unknown',router);`,
    `const other=express.Router();router.use(other);other.use(router);app.use('/',router);`,
  ]){
    const r=analyze({files:[{filePath:'server.js',content:`const express=require('express');const app=express(),router=express.Router();
      router.post('/',(req,res)=>res.end(),(req,res)=>eval(req.body.value));${setup}`} ]});
    assert.equal(findings(r).length,1);assert.equal(proof(r).length,0);
  }
});

test('unknown callbacks after a blocker and implicit function completion remain outside the proof contract',()=>{
  const r=analyze({files:[{filePath:'server.js',content:`const app=require('express')();app.post('/',(req,res)=>res.end(),external,(req,res)=>eval(req.body.value));`}]});
  assert.equal(findings(r).length,1);assert.equal(proof(r).length,0);
});

test('earlier routes and mounted routers cannot silently mutate the response contract',()=>{
  for(const before of [
    `app.post('/',(req,res,next)=>{req.url='/';res.end=external;next('route');});`,
    `const prior=express.Router();prior.use(external);app.use('/',prior);`,
  ]){
    const r=analyze({files:[{filePath:'server.js',content:`const express=require('express');const app=express();${before}
      app.post('/',(req,res)=>res.end(),(req,res)=>eval(req.body.value));`} ]});
    assert.equal(findings(r).length,1);assert.equal(proof(r).length,0);
  }
  const normal=analyze({files:[{filePath:'server.js',content:`const app=require('express')();app.get('/health',(req,res)=>res.json({ok:true}));
    app.post('/',(req,res)=>res.end(),(req,res)=>eval(req.body.value));`} ]});
  assert.equal(findings(normal).length,0);assert.equal(proof(normal).length,1);
});

test('local path/step limits cannot produce a successful suppression',()=>{
  const branches=Array.from({length:6},(_,i)=>`if(req.query.k${i})res.end();`).join('');
  const code=`const app=require('express')();app.post('/',(req,res,next)=>{${branches}next();},(req,res)=>eval(req.body.value));`;
  const r=analyze({files:[{filePath:'server.js',content:code}]});
  assert.equal(findings(r).length,1);assert.equal(proof(r).length,0);
  assert.ok(r.files[0].limitations.includes('EXPRESS_MIDDLEWARE_CONTROL_BUDGET_OR_UNSUPPORTED'));
  const limited=analyze(input(middlewareCases[0]),{maxSteps:15});
  assert.equal(proof(limited).length,0);assert.equal(limited.status,'PARTIAL');
});
