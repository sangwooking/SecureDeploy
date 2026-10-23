import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const rule='JS_SEQUELIZE_SQL_INPUT_FLOW';
const run=(body,extra=[],version='^4.13.10',overrides={})=>{
  const files=[{filePath:'server.cjs',content:`const express=require('express');const Sequelize=require('sequelize');const db=new Sequelize('unused');const app=express();app.post('/search',(req,res)=>{${body}});`},...extra];
  return analyze({files,nodeManifests:[{filePath:'package.json',express:'^4.16.2',sequelize:version}],
    nodeSourceInventory:files.map(f=>f.filePath),nodeSourceInventoryComplete:true,...overrides});
};
const strong=r=>r.findings.filter(f=>f.ruleId===rule&&f.confidence==='HIGH');
for(const [name,body] of Object.entries({
  concatenation:`db.query('SELECT * FROM items WHERE value='+req.body.value);`,
  template:'db.query(`SELECT * FROM items WHERE value=${req.body.value}`);',
  helper:`function query(v){return 'SELECT * FROM items WHERE value='+v} const alias=db;alias.query(query(req.body.value));`,
  bindingAfterConcat:`db.query('SELECT * FROM items WHERE value='+req.body.value,{bind:[req.body.value]});`,
}))test(`Sequelize confirmed input: ${name}`,()=>{
  const r=run(body);assert.equal(strong(r).length,1,JSON.stringify(r.files));
  assert.equal(strong(r)[0].kind,'CWE-89');
  assert.ok(r.nodeUses.some(u=>u.ruleId===rule&&u.kind==='INPUT_TO_EXECUTION'));
});
for(const [name,body] of Object.entries({
  static:`db.query('SELECT 1');`,
  binding:`db.query('SELECT * FROM items WHERE value=$1',{bind:[req.body.value]});`,
  replacements:`db.query('SELECT * FROM items WHERE value=:value',{replacements:{value:req.body.value}});`,
  overwrite:`let q=req.body.value;q='SELECT 1';db.query(q);`,
  otherMethod:`const other={query(v){return v}};other.query(req.body.value);`,
}))test(`Sequelize no input in SQL: ${name}`,()=>assert.equal(strong(run(body)).length,0));
for(const [name,body,version] of [
  ['unknown transformation',`db.query(clean(req.body.value));`,'^4.13.10'],
  ['unknown version',`db.query(req.body.value);`,'latest'],
  ['unsupported major',`db.query(req.body.value);`,'^7.0.0'],
  ['mutated receiver',`db.query=other;db.query(req.body.value);`,'^4.13.10'],
  ['escaped receiver',`external(db);db.query(req.body.value);`,'^4.13.10'],
  ['detached query',`const execute=db.query;execute(req.body.value);`,'^4.13.10'],
  ['unknown query options',`db.query(req.body.value,{hooks:external});`,'^4.13.10'],
])test(`Sequelize uncertainty: ${name}`,()=>assert.equal(strong(run(body,[],version)).length,0));

function registry(options={}){
  const files=[
    {filePath:'server.cjs',content:`const express=require('express');const db=require('./records');const app=express();app.post('/search',(req,res)=>db.sequelize.query('SELECT * FROM items WHERE id='+req.body.id,{model:db.Item}));`},
    {filePath:'records/index.js',content:`'use strict';var fs=require('fs');var path=require('path');var Engine=require('sequelize');var config=require('../settings');
      if(process.env.DB_URL){var connection=new Engine(process.env.DB_URL);}else{var connection=new Engine(config.database,config.username,config.password,{host:config.host,dialect:config.dialect});}
      connection.authenticate().then(function(err){console.log('ok')}).catch(function(err){console.log('failed')});
      connection.sync().then(function(err){console.log('ok')},function(err){console.log('failed')});
      var registry={};fs.readdirSync(__dirname).filter(function(file){return(file.indexOf('.')!==0)&&(file!=='index.js');}).forEach(function(file){var model=connection.import(path.join(__dirname,file));registry[model.name]=model;});
      Object.keys(registry).forEach(function(modelName){if('associate' in registry[modelName]){registry[modelName].associate(registry);}});
      registry.sequelize=connection;registry.Sequelize=Engine;module.exports=registry;`},
    {filePath:'records/item.js',content:`module.exports=function(client,Types){var Item=client.define('Item',{id:{type:Types.INTEGER}},{timestamps:false});return Item;};`},
    {filePath:'settings.js',content:`module.exports={database:process.env.DB_NAME||'unused',username:process.env.DB_USER,password:process.env.DB_PASSWORD,host:process.env.DB_HOST,dialect:'mysql'};`},
  ];
  if(options.model)files[2].content=options.model;
  if(options.change)files[1].content=options.change(files[1].content);
  const inventory=files.map(f=>f.filePath);if(options.missing)inventory.push('records/missing.js');
  return analyze({files,nodeManifests:[{filePath:'package.json',express:'^4.16.2',sequelize:options.version??'^4.13.10'}],
    nodeSourceInventory:inventory,nodeSourceInventoryComplete:options.complete!==false,
    nodeEnumeratedDirectories:options.scoped?['records']:[]});
}
test('bounded registry initialization connects a branch-created instance after reviewed model definitions',()=>{
  const r=registry();assert.equal(strong(r).length,1,JSON.stringify(r.files));
  assert.ok(r.nodeUses.some(u=>u.operation==='SEQUELIZE_REGISTRY_SUMMARY'));
  const origins=strong(r)[0].flow.filter(p=>p.kind==='SEQUELIZE_DECLARED_INSTANCE_ORIGIN');
  assert.equal(origins.length,2);assert.ok(origins.every(p=>p.filePath==='records/index.js'&&p.line>1));
});
for(const [name,options] of [
  ['omitted model',{missing:true}],['incomplete inventory',{complete:false}],
  ['removed v6 import API',{version:'6.37.5'}],
  ['custom associate',{model:`module.exports=function(c,T){var M=c.define('Item',{id:{type:T.INTEGER}});M.associate=function(db){db.sequelize.query=other};return M;}`}],
  ['model hook',{model:`module.exports=function(c,T){return c.define('Item',{}, {hooks:{beforeFind:external}});}`}],
  ['extra initialization mutation',{change:s=>s.replace('module.exports=registry;','external(registry);module.exports=registry;')}],
  ['missing instance export',{change:s=>s.replace('registry.sequelize=connection;','')}],
  ['unexpected association effect',{change:s=>s.replace('registry[modelName].associate(registry);','external(registry);')}],
  ['prototype assignment',{change:s=>s.replace('module.exports=registry;','registry.__proto__=external;module.exports=registry;')}],
  ['callback shadows directory',{change:s=>s.replaceAll('function(file)','function(__dirname)').replaceAll("file.indexOf",'__dirname.indexOf').replaceAll("file!==",'__dirname!==').replaceAll('__dirname,file','__dirname,__dirname')}],
  ['callback shadows registry',{change:s=>s.replace('var model=','var registry=').replace('registry[model.name]=model','registry[registry.name]=registry')}],
])test(`registry refuses ${name}`,()=>assert.equal(strong(registry(options)).length,0));

test('ESM constructor import, a separate instance export and imported helper preserve supported SQL flow',()=>{
  const files=[{filePath:'server.mjs',content:`import express from 'express';import db from './store.mjs';import {sql} from './helper.mjs';const app=express();app.post('/',(req,res)=>db.query(sql(req.body.value)));`},
    {filePath:'store.mjs',content:`import {Sequelize} from 'sequelize';export default new Sequelize('unused');`},
    {filePath:'helper.mjs',content:`export function sql(v){return 'SELECT * FROM records WHERE id='+v;}`}];
  const r=analyze({files,nodeManifests:[{filePath:'package.json',express:'4.21.2',sequelize:'6.37.5'}]});
  assert.equal(strong(r).length,1);
});

test('constructor hooks cannot become a confirmed unmodified query contract',()=>{
  const r=analyze({files:[{filePath:'server.cjs',content:`const E=require('sequelize');const db=new E('unused',{hooks:{beforeQuery:external}});const express=require('express');const app=express();app.post('/',(req,res)=>db.query(req.body.value));`}],nodeManifests:[{filePath:'package.json',sequelize:'6.37.5',express:'4.21.2'}]});
  assert.equal(strong(r).length,0);
});

test('only a completed containing-directory inventory can replace an unrelated global exclusion',()=>{
  assert.equal(strong(registry({complete:false,scoped:true})).length,1);
  assert.equal(strong(registry({complete:false,scoped:true,missing:true})).length,0);
});
