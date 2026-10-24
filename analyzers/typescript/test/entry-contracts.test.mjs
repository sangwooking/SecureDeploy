import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const run=(main,extra=[],limits)=>analyze({files:[{filePath:'main.cjs',content:main},...extra]},limits);
const wrapper={filePath:'lib/web.js',content:`const express=require('express');
  module.exports=function(){return express();};
  module.exports.Router=()=>{const router=express.Router();return router;};`};
const high=r=>r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW'&&f.confidence==='HIGH');
const contexts=r=>r.nodeUses.filter(u=>u.ruleId==='JS_SERVER_ENTRY_CONTEXT');

test('verified function own Router field and returned router link across relative wrapper imports',()=>{
  for(const [expression,expected]of [['req.query.code',1],['Number(req.query.code)',0],['"fixed"',0],['clean(req.query.code)',0]]){
    const r=run(`const web=require('./lib/web');const app=web();const router=web.Router();
      router.post('/task',(req,res)=>eval(${expression}));app.use('/api',router);`,[wrapper]);
    assert.equal(high(r).length,expected,expression);
    assert.equal(r.files.reduce((n,f)=>n+f.entrypoints,0),1);
    assert.ok(contexts(r).some(u=>u.kind==='CALL_LINKED'));
    assert.ok(contexts(r).some(u=>u.kind==='ENTRY_REGISTERED'));
  }
});

test('unmounted routers and uncalled initialization exports never become HTTP entries',()=>{
  for(const main of [
    `const web=require('./lib/web');const router=web.Router();router.get('/',(req,res)=>eval(req.query.code));`,
    `const web=require('./lib/web');module.exports=()=>{const app=web();app.get('/',(req,res)=>eval(req.query.code));return app;};`
  ]){const r=run(main,[wrapper]);assert.equal(high(r).length,0);assert.equal(r.files.reduce((n,f)=>n+f.entrypoints,0),0);}
});

test('unwritten or mutated function properties cannot inherit the function call target',()=>{
  for(const main of [
    `const web=require('./lib/web');const app=web.RouterMissing();app.get('/',(req,res)=>eval(req.query.code));`,
    `const web=require('./lib/web');unknownMutation(web);const app=web();app.get('/',(req,res)=>eval(req.query.code));`,
    `const web=require('./lib/web');web.prototype={};const app=web();app.get('/',(req,res)=>eval(req.query.code));`
  ])assert.equal(high(run(main,[wrapper])).length,0);
});

test('partial imports and bounded importer depth remain uninspected, not fabricated callbacks',()=>{
  const missing=run(`const web=require('./missing');const app=web();app.get('/',(req,res)=>eval(req.query.code));`);
  assert.equal(high(missing).length,0);assert.ok(missing.files.some(f=>f.limitations.includes('CONTEXT_MISSING')));
  const deep=run(`const web=require('./one');web();`,[
    {filePath:'one.js',content:`module.exports=require('./two');`},
    {filePath:'two.js',content:`module.exports=require('./lib/web');`},wrapper],{maxDepth:1});
  assert.equal(high(deep).length,0);assert.ok(deep.files.some(f=>f.limitations.some(l=>l.includes('DEPTH'))));
});

const passport=`const auth=require('passport');const Bearer=require('passport-http-bearer').Strategy;`;
test('Passport callback binding and authenticate reference are not HTTP entry or authorization proof',()=>{
  const r=run(passport+`function verify(token,done){eval(token);done(null,{id:1});}
    function setup(){auth.use('session-check',new Bearer({},verify));}
    const gate=auth.authenticate('session-check');`);
  assert.equal(r.files[0].entrypoints,0);assert.equal(r.findings.length,0);
  assert.ok(contexts(r).some(u=>u.kind==='CALLBACK_BOUND'));
  assert.ok(contexts(r).some(u=>u.kind==='AUTHENTICATOR_REFERENCED'));
  assert.ok(contexts(r).every(u=>u.limitations.includes('INITIALIZATION_AND_REQUEST_DISPATCH_NOT_VERIFIED')));
});

test('Passport module-export callback locations are tracked without exposing a strategy string',()=>{
  const r=run(passport+`const callbacks=module.exports;callbacks.verify=function(token,done){done(null,false);};
    callbacks.setup=()=>auth.use('opaque-private-strategy',new Bearer({},callbacks.verify));`);
  const binding=contexts(r).find(u=>u.kind==='CALLBACK_BOUND');assert.equal(binding.trace.length,1);
  assert.equal(JSON.stringify(r).includes('opaque-private-strategy'),false);
});

test('untrusted Passport API names, shadowed imports and overwritten callbacks cannot claim a known binding',()=>{
  for(const code of [
    `const auth=require('not-passport');const Bearer=require('passport-http-bearer').Strategy;auth.use(new Bearer(()=>true));`,
    passport+`function setup(auth){auth.use(new Bearer(()=>true));}`,
    passport+`auth.use=other;auth.use(new Bearer(()=>true));`,
    passport+`const callbacks=module.exports;callbacks.verify=()=>true;callbacks.verify=other;auth.use(new Bearer(callbacks.verify));`
  ])assert.equal(contexts(run(code)).filter(u=>u.kind==='CALLBACK_BOUND').length,0);
});

test('external strategy registrations stay external and declarations remain budget-limited',()=>{
  const r=run(passport+`auth.authenticate('not-registered-here');`);
  assert.ok(contexts(r).some(u=>u.kind==='EXTERNAL_IMPLEMENTATION_UNKNOWN'));
  const limited=run(passport+`auth.use(new Bearer((token,done)=>done(null,false)));`,[],{maxSteps:20});
  assert.equal(limited.findings.length,0);
  assert.ok(limited.files.some(f=>f.limitations.includes('ANALYSIS_STEP_BUDGET_EXCEEDED')));
});
