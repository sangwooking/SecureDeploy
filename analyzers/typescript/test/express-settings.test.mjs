import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const run=(body,extra=[])=>analyze({files:[{filePath:'start.cjs',content:body},...extra],nodeManifests:[{filePath:'package.json',express:'4.21.2'}]});
const pre="const express=require('express');const app=express();";
const count=r=>r.files.reduce((n,f)=>n+f.entrypoints,0);
test('a primitive fallback has no effects on unrelated receiver identity',()=>{
 for(const expression of ["process.env.PORT || 3001","process.env.PORT ?? 3001","process.env.FLAG && 'enabled'"]){
  const r=run(pre+`app.set('port',${expression});app.get('/work',(req,res)=>eval(req.query.value));app.get('port');`);
  assert.equal(count(r),1,expression);assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,1);
 }
});
test('setting reads after registration do not invalidate the known Express receiver',()=>{
 const r=run(pre+"app.get('/work',(req,res)=>eval(req.query.value));app.get('port');if(app.get('env')==='development'){app.use(external());}");
 assert.equal(count(r),1);assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW'&&f.confidence==='HIGH').length,1);
});
test('settings getter aliases preserve a mounted router and relative helper',()=>{
 const r=run(pre+"const alias=app;const router=require('./router');alias.use('/api',router);alias.get('port');",[
  {filePath:'router.js',content:"const router=require('express').Router();const {handle}=require('./logic');router.post('/work',handle);module.exports=router;"},
  {filePath:'logic.js',content:"exports.handle=(req,res)=>eval(req.body.value);"}]);
 assert.equal(count(r),1);assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW'&&f.confidence==='HIGH').length,1);
});
for(const [name,body]of [
 ['fixed-input',"eval('constant')"],
 ['overwritten-input',"let data=req.body.value;data='constant';eval(data)"],
])test('normal request after setting fallback: '+name,()=>{
 const r=run(pre+`app.set('port',process.env.PORT||3000);app.get('/work',(req,res)=>{${body}});app.get('port');`);
 assert.equal(count(r),1);assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,0);
});
for(const [name,code]of [
 ['lookalike',"const app={get(){}};app.get('env');app.get('/work',(req,res)=>eval(req.body.value));"],
 ['modified-method',pre+"app.get=custom;app.get('env');app.get('/work',(req,res)=>eval(req.body.value));"],
 ['escaped-receiver',pre+"patch(app);app.get('env');app.get('/work',(req,res)=>eval(req.body.value));"],
 ['effectful-fallback',pre+"const setting=process.env.PORT||patch(app);app.get('/work',(req,res)=>eval(req.body.value));"],
 ['dynamic-require',"const express=require(moduleName);const app=express();app.get('env');app.get('/work',(req,res)=>eval(req.body.value));"],
 ['no-request',pre+"app.get('port');app.get('env');"],
 ['unmounted-router',"const router=require('express').Router();router.get('env');router.get('/work',(req,res)=>eval(req.body.value));"],
])test('unproven request registration is not promoted: '+name,()=>{
 const r=run(code);assert.equal(count(r),0);assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,0);
});
test('primitive fallback keeps input uncertainty and does not certify external transformations',()=>{
 const r=run(pre+"app.set('port',process.env.PORT||3000);app.get('/work',(req,res)=>eval(transform(req.body.value)||'constant'));app.get('env');");
 assert.equal(count(r),1);assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,0);
 assert.ok(r.findings.some(f=>f.confidence==='MEDIUM')||r.files.some(f=>f.flowStatus==='PARTIAL'));
});
