import {test} from 'node:test';import assert from 'node:assert/strict';import {analyze,evaluatePipeline} from '../analyzer.mjs';
const pkg={filePath:'package.json',resolutionStatus:'PARSED',moduleType:'module',express:'4.21.2',next:'15.4.0'};
const run=(sources,limits)=>analyze({files:Object.entries(sources).map(([filePath,content])=>({filePath,content})),nodeManifests:[pkg]},limits);
const high=r=>r.findings.filter(f=>['JS_EVAL_INPUT_FLOW','TS_SSRF_INPUT_FLOW'].includes(f.ruleId)&&f.confidence==='HIGH');
const main="import express from 'express';import * as handling from './handling.mjs';const api=express();";
test('namespace callback and its argument/return helper preserve source and sink in separate files',()=>{
 const input={'entry.mjs':main+"api.put('/render',handling.render);",'handling.mjs':"import {pass} from './pass.mjs';export function render(req,res){eval(pass(req.body.expression));}",'pass.mjs':"export function pass(value){return value;}"};
 const r=run(input);assert.equal(high(r).length,1);assert.equal(high(r)[0].source.filePath,'handling.mjs');assert.ok(high(r)[0].flow.some(l=>l.filePath==='pass.mjs'));
 assert.ok(r.nodeUses.some(u=>u.kind==='ENTRY_REGISTERED'&&u.location.filePath==='entry.mjs'&&u.trace.some(l=>l.filePath==='handling.mjs')));
 assert.equal(r.files.find(f=>f.filePath==='entry.mjs').flowStatus,'PARTIAL');assert.ok(!r.files[0].limitations.includes('NO_SUPPORTED_SERVER_ENTRY_OR_CALL'));
 const inputObject={files:Object.entries(input).map(([filePath,content])=>({filePath,content})),nodeManifests:[pkg]};const audited=evaluatePipeline(inputObject);assert.deepEqual(audited.analysis,r);
 assert.ok(audited.pipeline.calls.some(c=>c.status==='TARGET_LINKED'&&c.crossFile));assert.equal(audited.pipeline.completeDenominator,null);
});
test('namespace named barrel and mounted Router distinguish unmounted and blocked callbacks',()=>{
 const helper={'handling.mjs':"export {execute} from './execute.mjs';",'execute.mjs':"export function execute(req,res){eval(req.params.key);}"};
 for(const mounted of[true,false]){const r=run({'entry.mjs':main+"const nested=express.Router();nested.delete('/:key',handling.execute);"+(mounted?"api.use('/tools',nested);":""),...helper});assert.equal(high(r).length,mounted?1:0);}
 const blocked=run({'entry.mjs':main+"function end(req,res,next){return res.status(401).end();}api.post('/:key',end,handling.execute);",...helper});assert.equal(high(blocked).length,0);
});
test('namespace interoperability, mutated symbols, side-effectful initializers and cycles abstain',()=>{
 for(const helper of["exports.execute=(req,res)=>eval(req.query.x);","export function execute(req,res){eval(req.query.x);}throw Error('halt');","boot();export function execute(req,res){eval(req.query.x);}","export * from './other.mjs';"]){
  const r=run({'entry.mjs':main+"api.get('/',handling.execute);",'handling.mjs':helper,'other.mjs':"export function execute(req,res){eval(req.query.x);}"});assert.equal(high(r).length,0);
 }
 const mutated=run({'entry.mjs':main+"handling.execute=external;api.get('/',handling.execute);",'handling.mjs':"export function execute(req,res){eval(req.query.x);}"});assert.equal(high(mutated).length,0);
 const cycle=run({'entry.mjs':main+"api.get('/',handling.execute);",'handling.mjs':"export {execute} from './cycle.mjs';",'cycle.mjs':"export {execute} from './handling.mjs';"});assert.equal(high(cycle).length,0);
});
test('Next method alias and two static re-exports retain route registration and helper sink locations',()=>{
 const files={'app/api/deliver/route.ts':"export {deliver as PATCH} from '../../logic/index.ts';",'app/logic/index.ts':"export {deliver} from './deliver.ts';",'app/logic/deliver.ts':"export async function deliver(req:Request){await fetch(new URL(req.url).searchParams.get('target'));return Response.json({ok:true});}"};
 const r=run(files);assert.equal(high(r).length,1);assert.equal(high(r)[0].sink.filePath,'app/logic/deliver.ts');assert.equal(r.authorizationContexts[0].entry.filePath,'app/api/deliver/route.ts');
 assert.ok(r.nodeUses.some(u=>u.operation==='NEXT_STATIC_NAMED_HANDLER'&&u.trace[0].filePath==='app/logic/deliver.ts'));
 assert.ok(r.files.find(f=>f.filePath==='app/api/deliver/route.ts').limitations.includes('REGISTERED_HANDLER_BODY_IN_OTHER_FILE'));
 assert.deepEqual(run(files),r);assert.equal(run(files,{maxSteps:10}).status,'PARTIAL');
});
test('Next local export list works without turning unused helpers into HTTP endpoints',()=>{
 const helper="export function handle(req:Request){return fetch(new URL(req.url).searchParams.get('destination'));}";
 const r=run({'app/api/v/route.ts':"import {handle} from '../../logic/handle.ts';export {handle as DELETE};",'app/logic/handle.ts':helper,'tools/unused.ts':"export function GET(req){return fetch(new URL(req.url).searchParams.get('destination'));}"});assert.equal(high(r).length,1);assert.equal(r.authorizationContexts.length,1);
});
test('Next client boundaries, wildcard/missing/cyclic exports and mutable callbacks are not trusted',()=>{
 for(const barrel of["'use client';export {handle} from './handle.ts';","export * from './handle.ts';","throw Error('halt');export {handle} from './handle.ts';","export {handle} from './missing.ts';"]){const r=run({'app/api/v/route.ts':"export {handle as GET} from '../../logic/index.ts';",'app/logic/index.ts':barrel,'app/logic/handle.ts':"export function handle(req){return fetch(new URL(req.url).searchParams.get('destination'));}"});assert.equal(high(r).length,0);}
 assert.equal(high(run({'app/api/v/route.ts':"let fn=(req)=>fetch(req.url);fn=unknown;export {fn as GET};"})).length,0);
});

test('cross-file pass-through keeps environment exposure parameter evidence as well as request taint',()=>{
 const r=run({'entry.mjs':main+"api.get('/state',handling.state);",'handling.mjs':"import {pass} from './pass.mjs';export function state(req,res){return res.json({ok:true,key:pass(process.env.API_SECRET)});}",'pass.mjs':"export function pass(v){return v;}"});
 const f=r.findings.find(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');assert.ok(f);assert.ok(f.flow.some(l=>l.filePath==='pass.mjs'&&l.kind==='FUNCTION_PARAMETER'));
});

test('large response evidence states its truncation without discarding the observed risk',()=>{
 const fields=Array.from({length:40},(_,i)=>`secret${i}:process.env.API_SECRET`).join(',');
 const r=run({'entry.mjs':"import express from 'express';const app=express();app.get('/state',(req,res)=>res.json({ok:true,"+fields+"}));"});
 const f=r.findings.find(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');assert.ok(f);assert.ok(f.limitations.includes('EXPOSURE_SOURCE_EVIDENCE_TRUNCATED'));assert.ok(f.limitations.includes('EXPOSURE_TRACE_DETAILS_TRUNCATED'));assert.equal(r.status,'PARTIAL');
 assert.ok(r.files[0].limitations.includes('EXPOSURE_SOURCE_EVIDENCE_TRUNCATED'));assert.ok(f.flow.length<=20);
});
