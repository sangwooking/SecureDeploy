import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {fileIoCases} from './file-io-promise-fixtures.mjs';
for(const c of fileIoCases)test(`file IO Promise: ${c.id}`,()=>{
 const r=analyze({files:c.files}),f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
 assert.equal(f.length,['HIGH','CONDITIONAL'].includes(c.expected)?1:0,c.id);
 if(c.expected==='HIGH')assert.equal(f[0].confidence,'HIGH');
 if(c.expected==='CONDITIONAL'){
  assert.equal(f[0].confidence,'MEDIUM');
  assert.ok(r.nodeUses.some(u=>u.kind==='FILE_IO_FULFILLMENT_POSSIBLE'));
  assert.ok(r.nodeUses.some(u=>u.kind==='REJECTION_PATH_POSSIBLE'));
  assert.ok(!r.nodeUses.some(u=>u.kind==='COMPLETION_CONFIRMED_BY_SUPPORTED_MODEL'));
 }
 if(c.expected==='UNKNOWN')assert.ok(r.files.some(f=>f.limitations.length>0));
 assert.deepEqual(analyze({files:c.files}),r);
});
test('two file operations keep distinct source positions without writing target files',()=>{
 const r=analyze({files:fileIoCases.find(c=>c.id==='two-writes').files});
 const io=r.nodeUses.filter(u=>u.kind==='FILE_IO_PROMISE_CREATED');
 assert.equal(io.length,2);assert.notEqual(io[0].location.column,io[1].location.column);
 assert.ok(io.every(u=>u.trace.some(t=>t.kind==='NATIVE_PROMISIFY_WRITEFILE')));
 assert.ok(r.nodeUses.some(u=>u.kind==='FILE_IO_FULFILLMENT_VALUE_UNDEFINED'));
});
test('immutable ESM aliases and a direct return wrapper preserve only conditional completion',()=>{
 const r=analyze({files:[{filePath:'entry.mjs',content:`import express from 'express';import {writeFile as save} from 'node:fs/promises';
 const app=express();async function write(){return save('unused.txt','data');}app.post('/',async(req,res)=>{await write();eval(req.body.code);});`}]});
 const f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');assert.equal(f.length,1);assert.equal(f[0].confidence,'MEDIUM');
});
test('post-await class state stays unverified and separate instances do not exchange input',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();const {writeFile}=require('fs/promises');
 class Store{constructor(v){this.value=v;}async save(){await writeFile('unused.txt','data');eval(this.value);}}
 app.post('/',(req,res)=>{const a=new Store(req.body.code);const b=new Store('1');a.save();b.save();});`}]});
 assert.equal(r.findings.length,0);assert.ok(r.files[0].limitations.includes('POST_AWAIT_HEAP_STATE_UNKNOWN'));
});
test('no custom symbol or reflected mutation is accepted as a native writeFile contract',()=>{
 for(const mutation of [`fs.writeFile[Symbol.for('nodejs.util.promisify.custom')]=external;`,`Object.defineProperty(fs.writeFile,'custom',{value:external});`,`const alias=fs;alias.writeFile=external;`]){
  const r=analyze({files:[{filePath:'entry.cjs',content:`const fs=require('fs');const {promisify}=require('util');${mutation}
  const write=promisify(fs.writeFile);const app=require('express')();app.post('/',async(req,res)=>{await write('unused.txt','data');eval(req.body.code);});`}]});
  assert.equal(r.findings.length,0,mutation);
 }
});
test('budget exhaustion cannot cache partial native provenance as trusted',()=>{
 const input={files:fileIoCases.find(c=>c.id==='promisified-write').files};
 const r=analyze(input,{maxSteps:40});assert.equal(r.findings.length,0);assert.ok(r.files.some(f=>f.limitations.length));
});
test('unrelated native promisify creation is not a writeFile mutation or a supported completion',()=>{
 const setup=`const fs=require('fs');const {promisify}=require('util');const read=promisify(fs.readFile);const write=promisify(fs.writeFile);const app=require('express')();`;
 const run=call=>analyze({files:[{filePath:'entry.cjs',content:setup+`app.post('/',async(req,res)=>{await ${call};eval(req.body.code);});`}]});
 assert.equal(run(`write('unused.txt','data')`).findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW'&&f.confidence==='MEDIUM').length,1);
 assert.equal(run(`read('unused.txt')`).findings.length,0);
});
test('unsupported overloads and altered promise tokens do not allow continuation',()=>{
 for(const code of [`await write('unused.txt',null);`,`await write('unused.txt',()=>{});`,`await write('unused.txt','data','not-an-encoding');`,`await write({},'data');`,`const p=write('unused.txt','data');p.then=external;await p;`]){
  const r=analyze({files:[{filePath:'entry.cjs',content:`const fs=require('fs');const {promisify}=require('util');const write=promisify(fs.writeFile);const app=require('express')();app.post('/',async(req,res)=>{${code}eval(req.body.code);});`}]});
  assert.equal(r.findings.length,0,code);
 }
});
test('conditional file write keeps post-await heap uncertainty after branch merge',()=>{
 const r=analyze({files:[{filePath:'entry.cjs',content:`const {writeFile}=require('fs/promises');const app=require('express')();
 app.post('/',async(req,res)=>{const holder={value:req.body.code};if(req.body.save)await writeFile('unused.txt','data');eval(holder.value);});`}]});
 assert.ok(r.findings.every(f=>f.confidence==='MEDIUM'));
 assert.ok(r.files[0].limitations.includes('OBJECT_BRANCH_MERGE_PARTIAL'));
});
test('a captured native promisified wrapper is distinct from later namespace uncertainty',()=>{
 const r=analyze({files:[{filePath:'entry.cjs',content:`const fs=require('fs');const {promisify}=require('util');const write=promisify(fs.writeFile);
 const app=require('express')();app.post('/',async(req,res)=>{if(!fs.existsSync('unused.txt'))await write('unused.txt','data');eval(req.body.code);});`}]});
 const f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');assert.equal(f.length,1);assert.equal(f[0].confidence,'MEDIUM');
 assert.ok(r.nodeUses.some(u=>u.kind==='FILE_IO_FULFILLMENT_POSSIBLE'));
});
test('short circuit forks retain an unchanged wrapper but not a changed or mixed callable',()=>{
 const base=`const fs=require('fs');const {promisify}=require('util');const write=promisify(fs.writeFile);const app=require('express')();
 app.post('/',async(req,res)=>{if(req.body.create&&!fs.existsSync('unused.txt')){CHANGE await write('unused.txt','data');eval(req.body.code);}});`;
 const run=change=>analyze({files:[{filePath:'entry.cjs',content:base.replace('CHANGE',change)}]});
 assert.equal(run('').findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW'&&f.confidence==='MEDIUM').length,1);
 assert.equal(run('write=external;').findings.length,0);
 const mixed=analyze({files:[{filePath:'entry.cjs',content:`const {writeFile}=require('fs/promises');const app=require('express')();app.post('/',async(req,res)=>{const p=req.body.other?writeFile('one','a'):external();await p;eval(req.body.code);});`}]});
 assert.equal(mixed.findings.length,0);
});
test('pending tokens and separate async instance invocations are not conflated',()=>{
 const pending=analyze({files:[{filePath:'entry.cjs',content:`const {writeFile}=require('fs/promises');const app=require('express')();app.post('/',async(req,res)=>{const a=writeFile('one','a');const b=writeFile('two','b');await a;await b;eval(req.body.code);});`}]});
 assert.equal(pending.findings.length,0);assert.ok(pending.files[0].limitations.includes('POST_AWAIT_HEAP_STATE_UNKNOWN'));
 const instances=analyze({files:[{filePath:'entry.cjs',content:`const {writeFile}=require('fs/promises');const app=require('express')();class Service{async save(value){await writeFile('unused.txt','data');eval(value);}}const a=new Service();const b=new Service();app.post('/',(req,res)=>{a.save(req.body.code);b.save('1');});`}]});
 const f=instances.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');assert.equal(f.length,1);assert.equal(f[0].confidence,'MEDIUM');
});
