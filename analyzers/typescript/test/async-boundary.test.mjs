import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {asyncCases} from './async-boundary-fixtures.mjs';
for(const c of asyncCases)test(`async boundary: ${c.id}`,()=>{
 const r=analyze({files:c.files}),f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
 assert.equal(f.length,['HIGH','CONDITIONAL'].includes(c.expected)?1:0,JSON.stringify(r.files));
 if(c.expected==='HIGH')assert.equal(f[0].confidence,'HIGH');
 if(c.expected==='CONDITIONAL')assert.equal(f[0].confidence,'MEDIUM');
 if(c.expected==='UNKNOWN')assert.ok(r.files.some(f=>f.limitations.length>0));
 assert.ok(r.nodeUses.some(u=>u.kind==='ASYNC_CALL_CONNECTED'));
 assert.deepEqual(analyze({files:c.files}),r);
});
test('post-await writes do not overwrite the callers synchronous instance state',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();
 class Service{constructor(){this.value='1';}async update(v){this.value=v;await 0;this.value='2';}}
 const service=new Service();app.post('/',(req,res)=>{service.update(req.body.code);eval(service.value);});`}]});
 const f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');assert.equal(f.length,1);assert.equal(f[0].confidence,'HIGH');
});
test('unsupported empty promise chains do not inherit a fulfilled token',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();app.post('/',async(req,res)=>{
 await Promise.resolve(0).then();eval(req.body.code);});`}]});
 assert.equal(r.findings.length,0);assert.ok(r.files[0].limitations.includes('UNSUPPORTED_ASYNC_BOUNDARY'));
});
test('async prefix forwards arguments across modules to existing shell and HTTP sinks',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();const work=require('./helper');
 app.post('/',(req,res)=>work(req.body.command,req.body.url));`},{filePath:'helper.js',content:`const {exec}=require('node:child_process');
 module.exports=async(command,url)=>{exec(command);fetch(url);await external();};`}]});
 assert.ok(r.findings.some(f=>f.ruleId==='JS_SHELL_COMMAND_INPUT_FLOW'&&f.confidence==='HIGH'));
 assert.ok(r.findings.some(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH'));
});
test('async prefix retains the existing Sequelize query and value binding contracts',()=>{
 const base=`const app=require('express')();const Sequelize=require('sequelize');const db=new Sequelize('unused');
 async function query(value){QUERY;await external();}app.post('/',(req,res)=>query(req.body.value));`;
 const run=q=>analyze({files:[{filePath:'entry.cjs',content:base.replace('QUERY',q)}],nodeManifests:[{filePath:'package.json',sequelize:'4.13.10'}]});
 assert.equal(run(`db.query('SELECT * FROM items WHERE value='+value)`).findings.filter(f=>f.ruleId==='JS_SEQUELIZE_SQL_INPUT_FLOW').length,1);
 assert.equal(run(`db.query('SELECT * FROM items WHERE value=$1',{bind:[value]})`).findings.filter(f=>f.ruleId==='JS_SEQUELIZE_SQL_INPUT_FLOW').length,0);
});
test('an unawaited rejected async call is not a synchronous constructor throw',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();async function fail(){throw Error('stop');}
 class Service{constructor(){fail();app.post('/',(req,res)=>eval(req.body.code));}}new Service();`}]});
 assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW').length,1);
});
test('a confirmed async prefix preserves sensitive response and file access observations',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();const fs=require('node:fs');
 class Service{async run(path,res){fs.readFileSync(path);res.json({value:process.env.API_SECRET});await external();}}
 const service=new Service();app.post('/',(req,res)=>service.run(req.body.path,res));`}]});
 assert.ok(r.findings.some(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE'&&f.confidence==='HIGH'));
 assert.ok(r.resourceUses.some(u=>u.trace.some(t=>t.kind==='EXPRESS_BODY')));
});
test('async recursion and suspension keep the existing depth and step limits',()=>{
 const c=asyncCases.find(c=>c.id==='class-pre-await');
 const r=analyze({files:c.files},{maxSteps:30});
 assert.ok(r.files.some(f=>f.limitations.length));
 const limited=analyze({files:asyncCases.find(c=>c.id==='native-resolve').files},{maxSteps:40});
 assert.equal(limited.findings.length,0);
 const loop=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();async function recurse(){return recurse();}
 app.post('/',async(req,res)=>{await recurse();eval(req.body.code);});`}]});
 assert.equal(loop.findings.length,0);assert.ok(loop.files[0].limitations.includes('CALL_DEPTH_EXCEEDED'));
});
test('mutated and escaped Promise instances cannot keep fulfillment proof',()=>{
 for(const mutation of [`p.constructor=external;`,`external(p);`]){
  const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();app.post('/',async(req,res)=>{
   const p=Promise.resolve(0);${mutation}await p;eval(req.body.code);});`}]});
  assert.equal(r.findings.length,0);assert.ok(r.files[0].limitations.includes('UNSUPPORTED_ASYNC_BOUNDARY'));
 }
});
test('a constructor throw inside async becomes rejection rather than aborting the caller bootstrap',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();
 class Broken{constructor(){throw Error('stop');}}async function fail(){new Broken();app.post('/unreachable',(req,res)=>eval(req.body.other));}
 class Service{constructor(){fail();app.post('/',(req,res)=>eval(req.body.code));}}new Service();`}]});
 assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW').length,1);
});
test('a synchronous function constructor throw stops its async caller prefix',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();function Broken(){throw Error('stop');}
 app.post('/',async(req,res)=>{new Broken();eval(req.body.code);});`}]});
 assert.equal(r.findings.length,0);
});
test('generator bodies are not activated by calls from async code',()=>{
 for(const kind of ['function*','async function*']){
  const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();${kind} values(v){eval(v);}
  app.post('/',async(req,res)=>values(req.body.code));`}]});
  assert.equal(r.findings.length,0);assert.ok(r.files[0].limitations.includes('GENERATOR_EXECUTION_NOT_MODELED'));
 }
});
