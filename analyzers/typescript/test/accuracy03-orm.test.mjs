import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import{evaluatePipeline}from'../analyzer.mjs';
const inputs=JSON.parse(fs.readFileSync(new URL('../../../scripts/evaluation/accuracy03-orm-inputs.json',import.meta.url))).cases;
for(const c of inputs)test('conditional ORM provenance: '+c.id,()=>{const r=evaluatePipeline(c.input).analysis;assert.equal(r.nodeUses.some(n=>n.kind==='SEQUELIZE_RESULT_CALLBACK_POSSIBLE'),c.expected);assert.ok(!r.findings.some(f=>/AUTHORIZATION|IDOR/.test(f.ruleId)));});
for(const[name,rewrite]of[
 ['unknown driver version',c=>c.input.nodeManifests[0].sequelize='*'],
 ['missing inventory',c=>{c.input.nodeSourceInventoryComplete=false;c.input.nodeEnumeratedDirectories=[];}],
 ['generator callback',c=>c.input.files[0].content=c.input.files[0].content.replace('rows=>res.json({label:req.query.label,rows})','function*(rows){yield res.json(rows)}')],
 ['async callback',c=>c.input.files[0].content=c.input.files[0].content.replace('then(rows=>','then(async rows=>')],
 ['promise mutation',c=>c.input.files[0].content="const express=require('express');const db=require('./models');const app=express();app.get('/items',(req,res)=>{const p=db.User.findAll({});p.then=other;p.then(rows=>res.json(rows));});"],
])test('ORM provenance fails closed: '+name,()=>{const c=structuredClone(inputs[0]);rewrite(c);const r=evaluatePipeline(c.input).analysis;assert.ok(!r.nodeUses.some(n=>n.kind==='SEQUELIZE_RESULT_CALLBACK_POSSIBLE'));});

for(const mutation of ["Promise.prototype.then=other;", "Object.defineProperty(Promise.prototype,'then',{value:other});"])
 test('known prototype mutation blocks callback proof: '+mutation,()=>{const c=structuredClone(inputs[0]);c.input.files[0].content=mutation+c.input.files[0].content;assert.ok(!evaluatePipeline(c.input).analysis.nodeUses.some(n=>n.kind==='SEQUELIZE_RESULT_CALLBACK_POSSIBLE'));});
test('unrelated vendor text does not block server callback proof',()=>{const c=structuredClone(inputs[0]);c.input.files.push({filePath:'client-vendor.js',content:"/* prototype then library notes */"});assert.ok(evaluatePipeline(c.input).analysis.nodeUses.some(n=>n.kind==='SEQUELIZE_RESULT_CALLBACK_POSSIBLE'));});
