import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {conditionalConstructorCases} from './conditional-constructor-fixtures.mjs';
for(const c of conditionalConstructorCases)test(`conditional constructor: ${c.id}`,()=>{
 const r=analyze({files:c.files});const f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
 assert.equal(f.length,c.truth==='TWO_CONDITIONAL'?2:['HIGH','CONDITIONAL'].includes(c.truth)?1:0,JSON.stringify(r.files));
 if(c.truth==='HIGH')assert.ok(f.every(f=>f.confidence==='HIGH'));
 if(c.truth.includes('CONDITIONAL'))assert.ok(f.every(f=>f.confidence==='MEDIUM'));
 if(c.truth==='NORMAL')assert.ok(r.files.some(f=>f.entrypoints>0));
 if(c.truth==='UNKNOWN')assert.ok(r.files.some(f=>f.limitations.length>0));
 assert.deepEqual(analyze({files:c.files}),r);
});
test('an explicit helper throw aborts only its constructor chain',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();class Service{
  constructor(app){this.app=app;this.fail();this.register();}
  fail(){throw Error('stop');}register(){this.app.post('/',(req,res)=>eval(req.body.code));}}
  new Service(app);app.post('/later',(req,res)=>eval(req.body.code));`}]});
 assert.equal(r.findings.length,0);assert.equal(r.files[0].entrypoints,0);
 assert.ok(r.files[0].limitations.includes('CLASS_CONSTRUCTOR_THROW_PROVEN'));
});
test('conditional completion cannot become an unconditional instance method proof',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();class Service{
  constructor(app,enabled){this.app=app;if(enabled)throw Error('stop');}
  register(){this.app.post('/',(req,res)=>eval(req.body.code));}}
  const service=new Service(app,external);service.register();`}]});
 assert.equal(r.findings.length,1);assert.equal(r.findings[0].confidence,'MEDIUM');
});
test('constructor branch exploration consumes the existing budgets',()=>{
 const c=conditionalConstructorCases.find(c=>c.id==='unknown-both-handlers');
 for(const budget of [{maxSteps:30},{maxDepth:1},{maxResults:1}]){
  const r=analyze({files:c.files},budget);
  assert.ok(r.files.some(f=>f.limitations.length>0));
  assert.ok(r.findings.every(f=>f.confidence!=='HIGH'));
 }
});
test('constructor conditions connect direct async prefixes but never activate promise callbacks',()=>{
 for(const [body,entries]of [
  [`async function activate(){app.post('/',(req,res)=>eval(req.body.code));}class Service{constructor(){if(true)activate();}}new Service();`,1],
  [`class Service{constructor(){if(true)Promise.resolve().then(()=>app.post('/',(req,res)=>eval(req.body.code)));}}new Service();`,0],
 ]){
  const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();`+body}]});
  assert.equal(r.findings.length,entries);assert.equal(r.files[0].entrypoints,entries);
  assert.ok(r.files[0].limitations.length>0);
 }
});
test('an earlier conditional return is not overwritten by a later throw completion',()=>{
 const pre=`const app=require('express')();class Service{constructor(app,flag){this.app=app;if(flag)return;throw Error('stop');}
 register(){this.app.post('/',(req,res)=>eval(req.body.code));}}`;
 const r=analyze({files:[{filePath:'entry.js',content:pre+`const service=new Service(app,external);service.register();`}]});
 assert.equal(r.findings.length,1);assert.equal(r.findings[0].confidence,'MEDIUM');
});
test('a registration on the throw-only continuation is incompatible with the returning path',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();class Service{
 constructor(app,flag){this.app=app;if(flag)return;this.register();throw Error('stop');}
 register(){this.app.post('/',(req,res)=>eval(req.body.code));}}new Service(app,external);`}]});
 assert.equal(r.findings.length,0);assert.ok(r.nodeUses.some(u=>u.operation==='CONSTRUCTOR_THROW_BEFORE_COMPLETION'));
});
test('constructor throws stop later expression operands, arguments and initializers',()=>{
 const route=`app.post('/',(req,res)=>eval(req.body.code))`;
 for(const tail of [
  `new Broken(),${route};`,
  `unknown(new Broken(),${route});`,
  `const first=new Broken(),second=${route};`,
  `if(new Broken())${route};`,
  `new Broken()?${route}:${route};`,
 ]){
  const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();class Broken{constructor(){throw Error('stop');}}${tail}`}]});
  assert.equal(r.findings.length,0,tail);assert.equal(r.files[0].entrypoints,0,tail);
 }
});
