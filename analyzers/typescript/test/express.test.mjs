import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../analyzer.mjs';

const run = (code, extra = [], limits) => analyze({ files: [{ filePath: 'server.cjs', content: code }, ...extra],
  nodeManifests: [{ filePath: 'package.json', mongodb: '^2.2.0', express: '^4.18.0' }] }, limits);
const express = code => `const express=require('express'); const app=express(); ${code}`;
const strong = r => r.findings.filter(f => f.confidence === 'HIGH' && ['JS_EVAL_INPUT_FLOW','JS_MONGO_WHERE_INPUT_FLOW'].includes(f.ruleId));

test('verified Express request registration distinguishes input eval from static, numeric and unknown values', () => {
  for (const [expression, expected] of [['req.query.code',1],['req.body.code',1],['req.params.code',1],['"1+2"',0],['Number(req.query.code)',0],['sanitize(req.query.code)',0]]) {
    const r=run(express(`app.post('/run/:code',(req,res)=>{eval(${expression});});`));
    assert.equal(strong(r).length,expected,expression);
    assert.equal(r.files[0].entrypoints,1);
  }
});
test('unproven routers, shadowed eval and disconnected handlers are not request execution proofs', () => {
  for(const code of [`app.get('/',(req,res)=>eval(req.query.code));`,
    express(`function eval(x){return x};app.get('/',(req,res)=>eval(req.query.code));`),
    express(`const router=express.Router();router.get('/',(req,res)=>eval(req.query.code));`),
    `function test(req){eval(req.body.code)}`])assert.equal(strong(run(code)).length,0);
});
test('static Router mount and ESM module handler preserve source and destination', () => {
  const r=run(`import express from 'express';import {handler} from './handler.mjs';const app=express();const router=express.Router();router.post('/run',handler);app.use('/api',router);`,
    [{filePath:'handler.mjs',content:'export function handler(req,res){const code=req.body.code;eval(code)}'}]);
  assert.equal(strong(r).length,1);assert.equal(strong(r)[0].sink.filePath,'handler.mjs');
  const defaults=run(`import express from 'express';import handler from './handler.mjs';const app=express();app.get('/',handler);`,[{filePath:'handler.mjs',content:'export default function handle(req,res){eval(req.query.code)}'}]);
  assert.equal(strong(defaults).length,1);
});
test('CommonJS registration, constructor member and DAO closure connect only static Mongo collection calls', () => {
  const r=run(express(`const routes=require('./routes');const MongoClient=require('mongodb').MongoClient;MongoClient.connect('unused',(err,db)=>{routes(app,db)});`),[
    {filePath:'routes.cjs',content:`const Handler=require('./handler');module.exports=(app,db)=>{const h=new Handler(db);app.get('/items/:id',h.show);};`},
    {filePath:'handler.cjs',content:`const Store=require('./store').Store;function Handler(db){const store=new Store(db);this.show=(req,res)=>store.find(req.query.limit)}module.exports=Handler;`},
    {filePath:'store.cjs',content:`function Store(db){const collection=db.collection('items');this.find=(value)=>{const query=()=>({$where:'this.amount > '+value});return collection.find(query());};}module.exports.Store=Store;`},
  ]);
  assert.equal(strong(r).length,1);assert.equal(strong(r)[0].ruleId,'JS_MONGO_WHERE_INPUT_FLOW');
  assert.equal(strong(r)[0].kind,'CWE-943');assert.ok(strong(r)[0].flow.some(l=>l.kind==='FUNCTION_ARGUMENT'));
});
test('Mongo query execution, not a property name, is required', () => {
  for(const [query,expected]of [[`{$where:'this.a > '+req.query.value}`,1],[`{$where:'this.a > 3'}`,0],[`{value:req.query.value}`,0],[`{$where:'this.a > '+parseInt(req.query.value,10)}`,0]]) {
    const r=run(express(`const {MongoClient}=require('mongodb');MongoClient.connect('unused',(err,db)=>{const c=db.collection('items');app.get('/',(req,res)=>c.find(${query}));});`));
    assert.equal(strong(r).length,expected,query);
  }
  assert.equal(strong(run(express(`app.get('/',(req,res)=>{const query={$where:req.query.code};return fake.find(query)});`))).length,0);
});
test('captured reassignment and unknown transformations cannot yield confirmed input execution', () => {
  const r=run(express(`app.get('/',(req,res)=>{let x=req.query.code;const apply=()=>eval(x);x='1';apply();});`));
  assert.equal(strong(r).length,0);
  assert.equal(strong(run(express(`app.get('/',(req,res)=>{if(!validate(req.query.code))return;eval(req.query.code);});`))).length,0);
});
test('documented Express locals and HTTP server adapter do not replace the router identity',()=>{
  const r=run(express(`const http=require('node:http');const {MongoClient}=require('mongodb');MongoClient.connect('unused',(err,db)=>{app.locals.renderer=external;app.get('/',(req,res)=>eval(req.query.code));http.createServer(app).listen(0);});`));
  assert.equal(strong(r).length,1);
});
test('conditional query factory and function-expression constructor retain distinct query alternatives',()=>{
  const r=run(express(`const {MongoClient}=require('mongodb');const Store=function(db){if(false===(this instanceof Store))return new Store(db);const c=db.collection('items');this.find=(input)=>{const build=()=>{if(input)return {$where:'this.x > '+input};return {x:1};};return c.find(build());};};MongoClient.connect('unused',(err,db)=>{const store=new Store(db);app.get('/',(req,res)=>store.find(req.query.value));});`));
  assert.equal(strong(r).filter(f=>f.ruleId==='JS_MONGO_WHERE_INPUT_FLOW').length,1,JSON.stringify(r.files));
});
