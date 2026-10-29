import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {classCases} from './class-bootstrap-fixtures.mjs';
for(const c of classCases)test(`class bootstrap: ${c.id}`,()=>{
  const r=analyze({files:c.files}),warnings=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
  assert.equal(warnings.length,c.truth==='RISK'?1:0,JSON.stringify(r.files));
  if(c.truth==='RISK'){
    assert.equal(warnings[0].confidence,'HIGH');assert.equal(warnings[0].source.kind,'EXPRESS_BODY');
    assert.ok(r.nodeUses.some(u=>u.kind==='CLASS_CONSTRUCTED'));
    assert.ok(r.files.reduce((n,f)=>n+f.entrypoints,0)>0);
  }
  if(c.truth==='NORMAL')assert.ok(r.nodeUses.some(u=>u.kind==='STATIC_OR_DATA_ONLY'));
  if(c.truth==='UNKNOWN')assert.ok(r.files.some(f=>f.limitations.length>0));
  assert.equal(r.files.some(f=>f.parseStatus==='PARSE_FAILED'),false);
  assert.deepEqual(analyze({files:c.files}),r);
});
test('class traversal uses existing depth and result budgets',()=>{
  const c=classCases.find(c=>c.id==='constructor-nested-method');
  const r=analyze({files:c.files},{maxDepth:1});
  assert.ok(r.files.some(f=>f.limitations.some(l=>l.includes('DEPTH'))));
  assert.equal(r.findings.length,0);
});
test('constructor function fields stay explicitly unsupported rather than losing this silently',()=>{
  const r=analyze({files:[{filePath:'server.js',content:`const app=require('express')();
    class Helper{constructor(){this.value='1';this.run=()=>eval(this.value);}}
    const h=new Helper();app.post('/a',(req,res)=>{if(req.query.enabled){h.value=req.body.code;h.run();}});
    app.post('/b',(req,res)=>h.run());`}]});
  assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW').length,0);
  assert.ok(r.files.some(f=>f.limitations.includes('CLASS_CONSTRUCTOR_CONTROL_FLOW_UNKNOWN')));
});
test('TypeScript parameter properties cannot masquerade as explicit field assignments',()=>{
  const r=analyze({files:[{filePath:'entry.ts',content:`const app=require('express')();
    class Service{constructor(public app){}register(){this.app.post('/',(req,res)=>eval(req.body.code));}}
    new Service(app).register();`}]});
  assert.equal(r.findings.length,0);
  assert.ok(r.files[0].limitations.includes('CLASS_PARAMETER_PROPERTY_OR_DECORATOR_UNKNOWN'));
});
test('binding a shared method to a different instance uses that instance only',()=>{
  const r=analyze({files:[{filePath:'entry.js',content:`const express=require('express');const app=express();
    class Service{constructor(app){this.app=app;}register(){this.app.post('/',(req,res)=>eval(req.body.code));}}
    const mounted=new Service(app),unmounted=new Service(express.Router());
    const f=mounted.register.bind(unmounted);f();`}]});
  assert.equal(r.findings.length,0);assert.equal(r.files[0].entrypoints,0);
});
test('constructor dispatch uses the actual own method, never a shadowed prototype method',()=>{
  const body=`const app=require('express')();class Service{
    constructor(app,handler){this.app=app;this.register=handler;this.register();}
    register(){this.app.post('/',(req,res)=>eval(req.body.code));}}
  `;
  const known=analyze({files:[{filePath:'entry.js',content:body+`new Service(app,()=>1);`}]});
  assert.equal(known.findings.length,0);assert.equal(known.files[0].entrypoints,0);
  const unresolved=analyze({files:[{filePath:'entry.js',content:body+`new Service(app,external);`}]});
  assert.equal(unresolved.findings.length,0);assert.equal(unresolved.files[0].entrypoints,0);
  assert.ok(unresolved.files[0].limitations.includes('CALL_TARGET_UNRESOLVED'));
});
test('changed this fields do not retain an earlier mounted app identity',()=>{
  const body=`const express=require('express');const app=express();class Service{
    constructor(app){this.app=app;}register(){this.app.post('/',(req,res)=>eval(req.body.code));}}
    const service=new Service(app);`;
  const changed=analyze({files:[{filePath:'entry.js',content:body+`service.app=express.Router();service.register();`}]});
  assert.equal(changed.findings.length,0);assert.equal(changed.files[0].entrypoints,0);
  const unresolved=analyze({files:[{filePath:'entry.js',content:body+`service.app=external;service.register();`}]});
  assert.equal(unresolved.findings.length,0);assert.equal(unresolved.files[0].entrypoints,0);
  assert.ok(unresolved.files[0].limitations.includes('CALL_TARGET_UNRESOLVED'));
});
test('registering a class callback on an external event does not execute it',()=>{
  const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();
    const events=require('events');const emitter=new events.EventEmitter();
    class Service{constructor(app){this.app=app;emitter.on('ready',()=>this.register());}
      register(){this.app.post('/',(req,res)=>eval(req.body.code));}}
    new Service(app);`}]});
  assert.equal(r.findings.length,0);assert.equal(r.files[0].entrypoints,0);
  assert.ok(r.files[0].limitations.includes('CALL_TARGET_UNRESOLVED'));
});
test('class discovery does not bypass the existing function, AST or step budgets',()=>{
  const c=classCases.find(c=>c.id==='constructor-route');
  for(const budget of [{maxFunctions:1},{maxSteps:30},{maxNodes:20}]){
    const r=analyze({files:c.files},budget);
    assert.equal(r.findings.length,0);
    assert.ok(r.status!=='COMPLETE');
    assert.ok(r.files.some(f=>f.limitations.length>0));
  }
});
