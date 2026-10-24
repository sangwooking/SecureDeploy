import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const run=body=>analyze({files:[{filePath:'server.cjs',content:`
const express=require('express');const app=express();
const {MongoClient}=require('mongodb');
${body}
`}],nodeManifests:[{filePath:'package.json',mongodb:'2.2.36'}]});
const confirmed=r=>r.findings.filter(f=>f.ruleId==='JS_MONGO_WHERE_INPUT_FLOW'&&f.confidence==='HIGH');
const setup=body=>`MongoClient.connect('unused',(err,db)=>{${body}});`;

test('unrelated earlier property uncertainty does not poison a later identity call',()=>{
  const r=run(setup(`const unrelated={};unrelated.x=1;
    function pass(value){return value;}
    const clean=pass(db);const c=clean.collection('items');
    app.get('/',(req,res)=>c.find({$where:'this.n > '+req.query.n}).toArray());`));
  assert.equal(confirmed(r).length,1);
});
test('constructor field, alias and returned collection retain confirmed origin',()=>{
  const r=run(setup(`function Store(database){this.database=database;this.collection=()=>this.database.collection('items');}
    const store=new Store(db);const alias=store;const c=alias.collection();
    app.get('/',(req,res)=>c.find({$where:'this.n > '+req.query.n}).toArray());`));
  assert.equal(confirmed(r).length,1);
});
test('unknown mutation and mixed receiver branches cannot establish origin',()=>{
  for(const code of [
    `const c=db.collection('items');external(c);`,
    `let c=db.collection('items');c=fake;`,
    `let c=db.collection('items');if(flag)c=fake;`,
    `const c={find:external};`,
  ]){
    const r=run(setup(`${code}app.get('/',(req,res)=>c.find({$where:req.query.code}).toArray());`));
    assert.equal(confirmed(r).length,0,code);
  }
});
test('known field writes and helper returns preserve query and receiver separately',()=>{
  const r=run(setup(`const box={};const alias=box;alias.db=db;
    function collection(box){return box.db.collection('items');}
    const c=collection(box);app.get('/',(req,res)=>{const q={};q.$where='this.n > '+req.query.n;c.find(q).toArray();});`));
  assert.equal(confirmed(r).length,1);
  assert.ok(confirmed(r)[0].flow.some(l=>l.kind==='MONGODB_COLLECTION_ORIGIN'));
});
test('fixed code, ordinary values and query creation without execution are not dangerous code flow',()=>{
  for(const action of [
    `c.find({$where:'this.n > 5'}).toArray();`,
    `c.find({n:req.query.n}).toArray();`,
    `const query={$where:req.query.code};res.json({ok:true});`,
  ])assert.equal(confirmed(run(setup(`const c=db.collection('items');app.get('/',(req,res)=>{${action}});`))).length,0);
});
test('effects through nested aliases or branch-local copies invalidate caller capabilities',()=>{
  for(const effect of [
    `function change(box){if(flag)external(box.collection);}change(box);`,
    `const change=value=>flag&&external(value.collection);change(box);`,
    `external(box);`,
  ]){
    const r=run(setup(`const box={collection:db.collection('items')};${effect}
      app.get('/',(req,res)=>box.collection.find({$where:req.query.code}).toArray());`));
    assert.equal(confirmed(r).length,0,effect);
  }
});
test('depth-limited constructor cannot leave a passed database falsely verified',()=>{
  const code=`const {MongoClient}=require('mongodb');const express=require('express');const app=express();
    function hidden(db){external(db);}
    function deep(db){hidden(db);}
    function mid(db){deep(db);}
    function start(db){mid(db);}
    MongoClient.connect('unused',(err,db)=>{start(db);const c=db.collection('items');
      app.get('/',(req,res)=>c.find({$where:req.query.code}).toArray());});`;
  const r=analyze({files:[{filePath:'nested.cjs',content:code}],nodeManifests:[{filePath:'package.json',mongodb:'2.2.36'}]});
  assert.equal(confirmed(r).length,0);
  assert.ok(r.files[0].limitations.includes('CALL_DEPTH_EXCEEDED'));
});
test('already loaded static exports remain available at a deeper import boundary',()=>{
  const r=analyze({files:[
    {filePath:'server.cjs',content:`const express=require('express');require('./common');const routes=require('./a');const app=express();app.get('/',routes.handler);`},
    {filePath:'common.js',content:`exports.handler=(req,res)=>eval(req.query.code);`},
    {filePath:'a.js',content:`module.exports=require('./b');`},
    {filePath:'b.js',content:`module.exports=require('./c');`},
    {filePath:'c.js',content:`module.exports=require('./common');`},
  ]});
  assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW'&&f.confidence==='HIGH').length,1);
});
