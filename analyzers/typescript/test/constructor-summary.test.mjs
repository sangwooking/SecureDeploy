import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const run=extra=>analyze({files:[{filePath:'server.cjs',content:`
const express=require('express');const {MongoClient}=require('mongodb');const app=express();
${extra}
`}],nodeManifests:[{filePath:'package.json',mongodb:'2.2.36'}]});
const strong=r=>r.findings.filter(f=>f.ruleId==='JS_MONGO_WHERE_INPUT_FLOW'&&f.confidence==='HIGH');

test('find cursor creation is not query execution, consumption is',()=>{
  for(const [consume,count]of [['',0],['.toArray()',1],['.next()',1],['.limit(3).sort({x:1}).toArray()',1]]){
    const r=run(`MongoClient.connect('unused',(err,db)=>{const c=db.collection('items');app.get('/',(req,res)=>c.find({$where:req.query.code})${consume});});`);
    assert.equal(strong(r).length,count,consume||'unconsumed');
  }
});
test('strict read-only constructor summary preserves a database across the depth boundary',()=>{
  const r=run(`function View(db){this.db=db;this.find=(q)=>this.db.collection('items').find({$where:q}).toArray();}
    function build(db){return new View(db);}function middle(db){return build(db);}function outer(db){return middle(db);}
    MongoClient.connect('unused',(err,db)=>{const view=outer(db);app.get('/',(req,res)=>view.find(req.query.code));});`);
  assert.equal(strong(r).length,1);
  assert.ok(r.nodeUses.some(u=>u.kind==='CONSTRUCTOR_SUMMARY_MUST'));
});
test('an unsupported constructor cannot claim a read-only summary',()=>{
  for(const effect of ['external(db);','if(flag)this.db=fake;','this[key]=db;']){
    const r=run(`function View(db){this.db=db;${effect}this.find=q=>this.db.collection('items').find({$where:q}).toArray();}
      function build(db){return new View(db);}function middle(db){return build(db);}function outer(db){return middle(db);}
      MongoClient.connect('unused',(err,db)=>{const view=outer(db);app.get('/',(req,res)=>view.find(req.query.code));});`);
    assert.equal(strong(r).length,0,effect);
  }
});
test('syntax-plan cache does not share database identity between calls',()=>{
  const r=run(`function Store(db){this.c=db.collection('items');this.query=q=>this.c.find({$where:q}).toArray();}
    function build(db){return new Store(db);}function middle(db){return build(db);}function outer(db){return middle(db);}
    MongoClient.connect('unused',(err,db)=>{const first=outer(db);const second=outer(fake);
      app.get('/first',(req,res)=>first.query(req.query.code));app.get('/second',(req,res)=>second.query(req.query.code));});`);
  assert.equal(strong(r).length,1);
});
test('constructor return objects and unknown factory effects do not retain a phantom this',()=>{
  for(const expression of ['return fake;','return {find:external};','return function alternate(){};','external(db);']){
    const r=run(`function Store(db){this.c=db.collection('items');this.query=q=>this.c.find({$where:q}).toArray();${expression}}
      MongoClient.connect('unused',(err,db)=>{const s=new Store(db);app.get('/',(req,res)=>s.query(req.query.code));});`);
    assert.equal(strong(r).length,0,expression);
  }
});
test('summary construction is still bounded by the existing step/function budgets',()=>{
  const files=[{filePath:'budget.cjs',content:`const e=require('express');const a=e();function S(v){this.v=v;this.read=q=>eval(q);}
    function b(v){return new S(v)}function c(v){return b(v)}function d(v){return c(v)}const s=d(1);a.get('/',r=>s.read(r.query.code));`}];
  for(const limits of [{maxSteps:20},{maxFunctions:1}]){
    const r=analyze({files},limits);assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,0);assert.equal(r.status,'PARTIAL');
  }
});
test('arrow, async and generator functions cannot establish a constructed instance',()=>{
  for(const definition of ['const Store=(db)=>{this.db=db;};','async function Store(db){this.db=db;}','function* Store(db){this.db=db;}']){
    const r=run(`${definition}MongoClient.connect('unused',(err,db)=>{const s=new Store(db);app.get('/',req=>s.db.collection('items').find({$where:req.query.code}).toArray());});`);
    assert.equal(strong(r).length,0);assert.ok(r.files[0].limitations.includes('NON_CONSTRUCTIBLE_FUNCTION_UNKNOWN'));
  }
});
