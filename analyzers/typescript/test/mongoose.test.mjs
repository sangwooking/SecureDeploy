import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {mongooseCases,mongooseInput} from './mongoose-cases.mjs';
const rule='JS_MONGOOSE_SELECTOR_INPUT_FLOW';
for(const c of mongooseCases)test('Mongoose selector: '+c.id,()=>{
  const r=analyze(c.input),fs=r.findings.filter(f=>f.ruleId===rule),uses=r.nodeUses.filter(u=>u.ruleId===rule);
  assert.equal(fs.length,c.truth==='RISK'?1:0,JSON.stringify({uses,files:r.files}));
  const status={RISK:'SELECTOR_INPUT_CANDIDATE',NORMAL:'STATIC_OR_STRING_FILTER',DEFENDED:'SANITIZE_FILTER_DECLARED',
    UNKNOWN:'UNKNOWN',CREATED:'QUERY_CREATED_EXECUTION_NOT_OBSERVED'}[c.truth];
  if(status)assert.ok(uses.some(u=>u.kind===status)||c.truth==='UNKNOWN'&&r.files.some(f=>f.limitations.some(l=>/MONGOOSE.*UNKNOWN/.test(l))),JSON.stringify({uses,files:r.files}));
  for(const u of uses){assert.ok(u.location.line>0);assert.ok(u.trace.length<=20);}
  for(const f of fs){assert.equal(f.disposition,'REVIEW_REQUIRED');assert.ok(f.flow.some(l=>l.kind==='EXPRESS_BODY'));
    assert.ok(f.flow.some(l=>l.kind==='MONGOOSE_MODEL_DECLARATION'));assert.ok(f.flow.some(l=>l.kind==='MONGOOSE_QUERY_EXECUTION_REQUEST'));}
  assert.deepEqual(analyze(c.input),r);
  assert.ok(!JSON.stringify(r).includes('public@example.invalid'));
});
test('explicit model registry retrieval and CommonJS exports preserve origin',()=>{
  const input=mongooseInput("await Model.findOne({email:req.body.email});",{define:"const Model=require('./model.cjs');",
    more:[{filePath:'model.cjs',content:"const m=require('mongoose');m.model('Account',new m.Schema({email:String}));module.exports=m.model('Account');"}]});
  assert.equal(analyze(input).findings.filter(f=>f.ruleId===rule).length,1);
});
test('static ESM default import and named model export preserve origin',()=>{
  const r=analyze({nodeManifests:[{filePath:'package.json',mongoose:'8.3.0',express:'4.18.0',moduleType:'module',resolutionStatus:'PARSED'}],files:[
    {filePath:'server.mjs',content:"import express from 'express';import {Account} from './model.mjs';const app=express();app.post('/',async(req,res)=>{await Account.find({email:req.body.email});});"},
    {filePath:'model.mjs',content:"import mongoose from 'mongoose';export const Account=mongoose.model('Account',new mongoose.Schema({email:String}));"}]});
  assert.equal(r.findings.filter(f=>f.ruleId===rule).length,1);
});
test('branch/config and escaping cannot retain a false sanitizer or model proof',()=>{
  for(const body of ["if(req.body.flag)m.set('sanitizeFilter',true);await Model.findOne({email:req.body.email});",
    "mutate(Model);await Model.findOne({email:req.body.email});",
    "const q=Model.findOne({email:req.body.email});configure(q);await q;"]){
    const r=analyze(mongooseInput(body));assert.equal(r.findings.filter(f=>f.ruleId===rule).length,0);
  }
});
test('request isolation, alias mutation and low budgets remain conservative',()=>{
  const input=mongooseInput("const alias=Model;alias.findOne=replacement;await Model.findOne(req.body);");
  assert.equal(analyze(input).findings.filter(f=>f.ruleId===rule).length,0);
  const limited=analyze(mongooseInput('await Model.findOne(req.body);'),{maxSteps:30});
  assert.equal(limited.findings.filter(f=>f.ruleId===rule).length,0);assert.notEqual(limited.status,'COMPLETE');
});
test('post-construction filter mutation cannot retroactively prove a safe query',()=>{
  for(const body of ["const f={email:req.body.email};const q=Model.findOne(f);f.email='fixed';await q;",
    "const f={email:'fixed'};const alias=f;const q=Model.findOne(f);alias.email=req.body.email;await q;"]){
    const r=analyze(mongooseInput(body));assert.equal(r.findings.filter(f=>f.ruleId===rule).length,0);
    assert.ok(r.nodeUses.some(u=>u.ruleId===rule&&u.kind==='UNKNOWN'));
  }
});
test('custom schema setters and shadowed schema types are unverified rather than risk proofs',()=>{
  for(const define of ["const Model=m.model('Record',new m.Schema({email:{type:String,set:clean}}));",
    "const String=customType;const Model=m.model('Record',new m.Schema({email:String}));"]){
    const r=analyze(mongooseInput('await Model.findOne(req.body);',{define}));
    assert.equal(r.findings.filter(f=>f.ruleId===rule).length,0);
    assert.ok(r.files.some(f=>f.limitations.includes('MONGOOSE_MODEL_REGISTRATION_UNKNOWN')));
  }
});
test('per-request global settings do not leak into another request entry',()=>{
  const base="const express=require('express');const m=require('mongoose');const app=express();const Model=m.model('Record',new m.Schema({email:String}));";
  const routes=["app.post('/one',async(req,res)=>{m.set('sanitizeFilter',true);await Model.findOne({email:req.body.email});});",
    "app.post('/two',async(req,res)=>{await Model.findOne({email:req.body.email});});"];
  for(const order of [routes,[...routes].reverse()]){
    const r=analyze({files:[{filePath:'server.cjs',content:base+order.join('')}],nodeManifests:[{filePath:'package.json',mongoose:'6.13.0',express:'4.18.0'}]});
    assert.equal(r.findings.filter(f=>f.ruleId===rule).length,1);
    assert.equal(r.nodeUses.filter(u=>u.ruleId===rule&&u.kind==='SANITIZE_FILTER_DECLARED').length,1);
  }
});
