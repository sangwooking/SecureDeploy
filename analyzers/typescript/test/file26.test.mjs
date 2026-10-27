import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {file26Cases} from './file26-cases.mjs';
const misses=new Set(['path-choice','path-prefix','path-replaced-after-check','path-realpath','path-originalname','next-filename']);
for(const c of file26Cases)test('file26 frozen control '+c.id,()=>{
 const r=analyze(c.input),hits=r.findings.filter(f=>f.ruleId==='JS_FILE_PATH_INPUT_FLOW'&&f.confidence==='HIGH');
 assert.equal(hits.length,c.track==='PATH'&&c.truth==='RISK'&&!misses.has(c.id)?1:0);
 const uses=r.resourceUses.filter(u=>u.ruleId==='JS_FILE_PATH_INPUT_FLOW');
 if(c.truth==='UNKNOWN'||misses.has(c.id))assert.ok(!uses.some(u=>u.kind==='STATIC_FILE_PATH'));
 if(c.truth==='NORMAL'&&!['path-relative-guard','path-lookalike'].includes(c.id))assert.ok(uses.some(u=>u.kind==='STATIC_FILE_PATH'));
 if(hits.length){assert.ok(hits[0].source.filePath);assert.ok(hits[0].sink.kind.startsWith('NODE_FILE_'));assert.equal(hits[0].kind,'CWE-22');}
});
test('proven named imports, module aliases and promises connect without loading targets',()=>{
 for(const code of [
  "import {readFileSync as read} from 'node:fs';const app=require('express')();app.get('/',(req,res)=>{read(req.query.name)});",
  "const fs=require('fs');const fsp=fs.promises;const app=require('express')();app.get('/',(req,res)=>{fsp.unlink(req.query.name)});",
  "const {readFileSync:read}=require('fs');const app=require('express')();app.get('/',(req,res)=>{read(req.query.name)});",
 ])assert.equal(analyze({files:[{filePath:'server.cjs',content:code}]}).findings.filter(f=>f.ruleId==='JS_FILE_PATH_INPUT_FLOW').length,1);
});
test('shared builtin mutation, type-only imports, descriptor options and resource limits fail closed',()=>{
 for(const body of [
  "const fsp=require('fs/promises');fs.promises.readFile=external;fsp.readFile(req.query.name);",
  "fs.createReadStream(req.query.name,{fd:3});",
  "fs.readFileSync({path:req.query.name});",
 ]){
  const c=file26Cases[0].input;const files=[{filePath:'server.cjs',content:c.files[0].content.replace('fs.readFileSync(req.query.name);',body)}];
  assert.equal(analyze({files}).findings.filter(f=>f.ruleId==='JS_FILE_PATH_INPUT_FLOW').length,0);
 }
 const code="import type {readFileSync} from 'node:fs';export async function POST(request){const p=await request.text();readFileSync(p)}";
 assert.equal(analyze({files:[{filePath:'app/api/x/route.ts',content:code}]}).findings.length,0);
 const limited=analyze(file26Cases[0].input,{maxSteps:2});assert.equal(limited.findings.length,0);
});
test('request-local builtin mutations do not leak into another entry analysis',()=>{
 const change="app.post('/a',(req,res)=>{const fs=require('fs');fs.readFileSync=external;});";
 const read="app.post('/b',(req,res)=>{const fs=require('fs');fs.readFileSync(req.query.name);});";
 for(const body of [change+read,read+change]){
  const r=analyze({files:[{filePath:'server.cjs',content:"const app=require('express')();"+body}]});
  assert.equal(r.findings.filter(f=>f.ruleId==='JS_FILE_PATH_INPUT_FLOW').length,1);
 }
});
