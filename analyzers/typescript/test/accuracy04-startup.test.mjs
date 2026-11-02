import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import {evaluatePipeline} from '../analyzer.mjs';
const cases=JSON.parse(fs.readFileSync(new URL('../../../scripts/evaluation/accuracy04-startup-inputs.json',import.meta.url))).cases;
const run=files=>evaluatePipeline({files,nodeManifests:[{filePath:'package.json',express:'4.21.2',sequelize:'4.44.4',moduleType:'commonjs',resolutionStatus:'PARSED'}]}).analysis;
for(const c of cases)test('frozen owned startup: '+c.id,()=>{const a=run(c.files),n=a.files.reduce((v,f)=>v+f.entrypoints,0);assert.equal(n,c.id==='await-helper'?0:['DIRECT','CONDITIONAL','TEST_ONLY'].includes(c.expected)?1:0);if(c.id==='await-helper')assert.ok(a.files.some(f=>f.limitations.includes('POST_AWAIT_HEAP_STATE_UNKNOWN')));if(c.id==='test-only')assert.ok(a.nodeUses.some(u=>u.limitations.includes('TEST_ONLY_NODE_ENV_BRANCH')));if(c.id==='service-concat')assert.ok(a.findings.some(f=>f.ruleId==='JS_SEQUELIZE_SQL_INPUT_FLOW'&&f.confidence==='MEDIUM'));if(c.id==='service-bound')assert.equal(a.findings.length,0);});
const pre="const app=require('express')();";
for(const [name,body] of [
 ['app-method-write',"const alias=app;alias.get=other;app.get('/x',(req,res)=>eval(req.query.x));"],
 ['alias-escape',"const alias=app;external(alias);app.get('/x',(req,res)=>eval(req.query.x));"],
 ['nested-alias-escape',"if(flag){const alias=app;external(alias);}app.get('/x',(req,res)=>eval(req.query.x));"],
 ['delete-method',"delete app.get;app.get('/x',(req,res)=>eval(req.query.x));"],
])test('conditional summary rejects '+name,()=>{const a=run([{filePath:'entry.cjs',content:pre+`function install(app){${body}}Promise.resolve().then(()=>install(app));`}]);assert.ok(!a.nodeUses.some(u=>u.kind==='STARTUP_ROUTE_REGISTRATION_POSSIBLE'));assert.ok(!a.findings.some(f=>f.confidence==='HIGH'));});
for(const mutation of ['delete Promise.prototype.then;','Promise.prototype.then=other;',"Object.defineProperty(Promise.prototype,'then',{value:other});"])
 test('native startup rejects mutation '+mutation,()=>{const a=run([{filePath:'entry.cjs',content:pre+mutation+"Promise.resolve().then(()=>app.get('/x',(req,res)=>eval(req.query.x)));"}]);assert.equal(a.files[0].entrypoints,0);});
test('dead branch/after return not summarized; aliases and static array paths preserved',()=>{const a=run([{filePath:'entry.cjs',content:pre+"function install(app){const renamed=app;if(false)app.get('/dead',(req,res)=>eval(req.query.x));renamed.get(['/a','/b'],(req,res)=>res.json({ok:true}));return;app.post('/dead2',(req,res)=>eval(req.query.x));}Promise.resolve().then(()=>install(app));"}]);assert.deepEqual(a.nodeUses.filter(u=>u.kind==='STARTUP_ROUTE_REGISTRATION_POSSIBLE').map(u=>u.operation),['GET /a','GET /b']);});

test('captured app mutation in helper blocks conditional summary',()=>{const a=run([{filePath:'entry.cjs',content:pre+"function tamper(){app.get=other;}function install(app){tamper();app.get('/x',(req,res)=>eval(req.query.x));}Promise.resolve().then(()=>install(app));"}]);assert.ok(!a.nodeUses.some(u=>u.kind==='STARTUP_ROUTE_REGISTRATION_POSSIBLE'));});
