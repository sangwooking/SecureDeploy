import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const start=`import express from 'express';const service=express();`;
const count=r=>r.findings.filter(f=>f.confidence==='HIGH'&&f.ruleId==='JS_EVAL_INPUT_FLOW').length;
test('later-authored Express variants separate danger, normal and deferred flow without a blind-evaluation claim',()=>{
  const rows=[
    ['RISK',`service.post('/a',(input,reply)=>eval(input.body.task));`],
    ['RISK',`function apply(v){return eval(v)}service.get('/a/:task',(input,reply)=>apply(input.params.task));`],
    ['RISK',`service.get('/a',(input,reply)=>{let v=input.query.task;let text='';text+=v;eval(text)});`],
    ['NORMAL',`service.get('/a',(input,reply)=>eval('2+2'));`],
    ['NORMAL',`service.get('/a',(input,reply)=>eval(Number(input.query.task)));`],
    ['NORMAL',`service.get('/a',(input,reply)=>{let v=input.query.task;v='2+2';eval(v)});`],
    ['UNKNOWN',`service.get('/a',(input,reply)=>eval(convert(input.query.task)));`],
    ['UNKNOWN',`service.get(dynamicRoute,(input,reply)=>eval(input.query.task));`],
    ['UNKNOWN',`service.get('/a',(input,reply)=>{if(!check(input.query.task))return;eval(input.query.task)});`],
  ];
  const totals={RISK:0,NORMAL:0,UNKNOWN:0};
  for(const [index,[label,body]]of rows.entries()){
    const r=analyze({files:[{filePath:`module${index}/app.${['js','mjs','cjs'][index%3]}`,content:start+body}]});
    assert.equal(count(r),label==='RISK'?1:0,`${label}/${index}`);totals[label]++;
    if(label==='UNKNOWN')assert.ok(r.files[0].limitations.length>0);
  }
  assert.deepEqual(totals,{RISK:3,NORMAL:3,UNKNOWN:3});
});
test('unknown framework identity, mutation and unavailable driver contracts never prove Mongo execution',()=>{
  for(const code of [`function require(x){return external};const e=require('express');const a=e();a.get('/',r=>eval(r.query.code));`,
    `const e=require('express');let a=e();mutate(a);a.get('/',r=>eval(r.query.code));`,
    `const e=require('express');function change(){e.Router=external}change();const a=e();a.get('/',r=>eval(r.query.code));`,
    `const e=require('express');const a=e();const {MongoClient}=require('unknown-driver');MongoClient.connect('',(err,db)=>{a.get('/',r=>db.collection('t').find({$where:r.query.code}));});`]) {
    const r=analyze({files:[{filePath:'app.js',content:code}]});assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,0);
  }
});
test('node source and target execution stay bounded under low work and depth budgets',()=>{
  const code=start+`function a(v){return b(v)}function b(v){return eval(v)}service.get('/',r=>a(r.query.code));`;
  for(const limits of [{maxDepth:1},{maxSteps:10},{maxFileChars:30},{maxFunctions:1}]){
    const result=analyze({files:[{filePath:'app.mjs',content:code}]},limits);
    assert.equal(count(result),0);assert.equal(result.status,'PARTIAL');
  }
});
test('type-only bindings and stopped initialization cannot establish executable Express registration',()=>{
  for(const code of [`import type express from 'express';const service=express();service.get('/',r=>eval(r.query.code));`,
    start+`throw new Error('stop');service.get('/',r=>eval(r.query.code));`,
    start+`if(false)service.get('/',r=>eval(r.query.code));`])assert.equal(count(analyze({files:[{filePath:'server.ts',content:code}]})),0);
});
