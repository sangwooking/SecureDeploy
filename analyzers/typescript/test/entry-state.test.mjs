import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {entryState} from '../entry-state.mjs';

const run=routes=>analyze({files:[{filePath:'server.cjs',content:`const express=require('express');const {MongoClient}=require('mongodb');const app=express();MongoClient.connect('unused',(err,db)=>{${routes}});`}],nodeManifests:[{filePath:'package.json',mongodb:'2.2.36'}]});
const confirmed=r=>r.findings.filter(f=>f.ruleId==='JS_MONGO_WHERE_INPUT_FLOW'&&f.confidence==='HIGH').length;

test('analysis of disjoint request entries must not depend on registration traversal order',()=>{
  const touch=`app.get('/touch',(req,res)=>unknownMutation(db));`;
  const query=`app.get('/query',(req,res)=>db.collection('items').find({$where:req.query.code}).toArray());`;
  assert.equal(confirmed(run(touch+query)),1);
  assert.equal(confirmed(run(query+touch)),1);
});

test('entry graphs preserve aliases, cyclic closures, lexical this and canonical function identity',()=>{
  const canonical=new WeakMap(), mod={}, node={}, ref={properties:new Map(),nodeIdentity:{}};
  const db={tag:'mongo-db',ref}, target={node,mod,closure:new Map(),lexicalThis:db};
  const fn={tag:'function',target};target.closure.set('self',fn);target.closure.set('db',db);
  ref.properties.set('handler',fn);
  const isolate=entryState(()=>{},canonical), a=isolate(fn), b=entryState(()=>{},canonical)(fn);
  assert.equal(a.target.closure.get('self'),a);
  assert.equal(a.target.closure.get('db'),a.target.lexicalThis);
  assert.equal(a.target.lexicalThis.ref.properties.get('handler'),a);
  assert.equal(canonical.get(a.target),target);
  assert.equal(a.target.node,node);assert.equal(a.target.mod,mod);
  assert.notEqual(a.target.lexicalThis.ref,b.target.lexicalThis.ref);
  assert.notEqual(a.target.lexicalThis.ref,ref);
});

test('same-entry collection alias mutations are not erased by entry isolation',()=>{
  assert.equal(confirmed(run(`const collection=db.collection('items');app.get('/query',(req,res)=>{
    const alias=collection;unknownMutation(alias);return collection.find({$where:req.query.code}).toArray();});`)),0);
});

test('closure and lexical this preserve a valid query in each independently analyzed route',()=>{
  const r=run(`function Repository(database){this.collection=database.collection('items');this.query=(input)=>this.collection.find({$where:input}).toArray();}
    const repo=new Repository(db);
    app.get('/touch',(req,res)=>unknownMutation(repo));
    app.get('/query',(req,res)=>repo.query(req.query.code));`);
  assert.equal(confirmed(r),1);
  assert.ok(r.files.some(f=>f.limitations.includes('MULTI_REQUEST_GLOBAL_LIFECYCLE_NOT_VERIFIED')));
  assert.equal(JSON.stringify(r).includes('nodeIdentity'),false);
  assert.equal(JSON.stringify(r).includes('isolate'),false);
});

test('runtime relative require uses the same entry graph as a captured import',()=>{
  const r=analyze({files:[{filePath:'server.cjs',content:`const express=require('express');
    const holder=require('./holder');const app=express();
      app.get('/touch',(req,res)=>unknownMutation(holder));
      app.get('/query',(req,res)=>{const second=require('./holder');unknownMutation(second);
        return holder.collection('items').find({$where:req.query.code}).toArray();});
      app.get('/clean',(req,res)=>holder.collection('items').find({$where:req.query.code}).toArray());`},
    {filePath:'holder.js',content:`const {MongoClient}=require('mongodb');const client=new MongoClient('unused');module.exports=client.db('test');`}],
    nodeManifests:[{filePath:'package.json',mongodb:'4.0.0'}]});
  assert.equal(confirmed(r),1);
});

test('entry graph copying consumes the existing analysis budget',()=>{
  const r=analyze({files:[{filePath:'server.cjs',content:`const app=require('express')();
    const data={a:{b:{c:1}}};app.get('/x',(req,res)=>data.a.b.c);`}]},{maxSteps:50});
  assert.notEqual(r.status,'COMPLETE');
  assert.ok(r.files.some(f=>f.limitations.some(l=>l.includes('BUDGET')||l.includes('LIMIT'))));
});
test('unknown mutation inside the same request cannot retain verified database origin',()=>{
  const r=run(`app.get('/query',(req,res)=>{unknownMutation(db);return db.collection('items').find({$where:req.query.code}).toArray();});`);
  assert.equal(confirmed(r),0);
});
