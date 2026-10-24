import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {moduleResolution} from '../module-resolution.mjs';

const factory=`const express=require('express');module.exports=()=>{const app=express();app.get('/',(req,res)=>eval(req.query.code));return app;};`;
function run(spec,extra,metadata=[],prefix='') {
  return analyze({files:[{filePath:'boot.js',content:`${prefix}const start=require(${JSON.stringify(spec)});start();`},...extra],
    nodeManifests:[{filePath:'package.json',resolutionStatus:'PARSED',mainStatus:'ABSENT',express:'4.18.0'},...metadata]});
}
const hits=r=>r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW'&&f.confidence==='HIGH').length;
const main=(main,extra={})=>({filePath:'service/package.json',resolutionStatus:'PARSED',mainStatus:'STATIC',main,...extra});
test('CommonJS root and nested directories resolve normalized index paths',()=>{
  for(const spec of ['.','./','./index','./index.js'])assert.equal(hits(run(spec,[{filePath:'index.js',content:factory}])),1,spec);
  assert.equal(hits(run('./service/',[{filePath:'service/index.js',content:factory}])) ,1);
});
test('main takes precedence, files precede directories and invalid main falls back to index',()=>{
  const files=[{filePath:'service/run.js',content:factory},{filePath:'service/index.js',content:'module.exports=()=>{};'}];
  assert.equal(hits(run('./service',files,[main('./run')])),1);
  assert.equal(hits(run('./service',files,[main('./missing')])),0);
  assert.equal(hits(run('./service',[{filePath:'service.js',content:'module.exports=()=>{};'},...files],[main('./run')])),0);
});
test('unknown configuration, workspace escape, dynamic and shadowed require never establish a route',()=>{
  const files=[{filePath:'service/index.js',content:factory}];
  for(const config of [main('../..'),main('./index',{resolutionStatus:'MALFORMED'}),main('./index',{mainStatus:'UNKNOWN'}),main('./index',{moduleType:'module'})])
    assert.equal(hits(run('./service',files,[config])),0);
  for(const spec of ['../../service','/service','./service%2findex.js'])assert.equal(hits(run(spec,files)),0);
  assert.equal(hits(run('./service',files,[],'function require(x){return ()=>{};}')),0);
  const r=analyze({files:[{filePath:'boot.js',content:`const start=require(target);start();`},...files]});assert.equal(hits(r),0);
});
test('omitted preferred source and JSON/native files block lower-priority fallback',()=>{
  for(const missing of ['service.js','service/package.json','service/index.json']){
    const files=[{filePath:'service/index.js',content:factory}];
    if(missing==='service/index.json')files[0].filePath='service/index.node';
    const r=analyze({files:[{filePath:'boot.js',content:`require('./service')();`},...files],nodeSourceInventory:[missing,...files.map(f=>f.filePath)]});
    assert.equal(hits(r),0,missing);
  }
});
test('ESM imports do not inherit CommonJS package main or directory fallback',()=>{
  for(const spec of ['./service','.']) {
    const r=analyze({files:[{filePath:'boot.mjs',content:`import start from '${spec}';start();`},{filePath:'service/index.js',content:factory},{filePath:'index.js',content:factory}],nodeManifests:[main('./index.js')]});
    assert.equal(hits(r),0,spec);
  }
});
test('CommonJS never appends cjs or ts and explicit cjs remains supported',()=>{
  for(const ext of ['cjs','ts'])assert.equal(hits(run('./service',[{filePath:'service.'+ext,content:factory}])),0);
  assert.equal(hits(run('./service.cjs',[{filePath:'service.cjs',content:factory}])),1);
});
test('directory inventory, malformed JSON and finite step budgets are not safety proofs',()=>{
  const files=[{filePath:'boot.js',content:`require('./service')();`},{filePath:'service/index.js',content:factory}];
  const r=analyze({files,nodeSourceInventory:files.map(f=>f.filePath),nodeSourceInventoryComplete:false});
  assert.equal(hits(r),0);assert.ok(r.files[0].limitations.includes('NODE_DIRECTORY_INVENTORY_INCOMPLETE'));
  const limited=analyze({files},{maxSteps:30});assert.equal(hits(limited),0);assert.equal(limited.status,'PARTIAL');
});
test('resolution unit contract distinguishes files, directory main, fallback and unsupported links',()=>{
  const modules=new Map(['boot.js','index.js','service.js','service/index.js','service/entry.cjs'].map(filePath=>[filePath,{filePath}]));
  const notes=[];const resolver=moduleResolution({modules,input:{nodeManifests:[main('./entry.cjs')]},tick(){},note(m,reason){notes.push(reason);}});
  const mod=modules.get('boot.js');
  assert.equal(resolver.resolve(mod,'.')?.filePath,'index.js');
  assert.equal(resolver.resolve(mod,'./service')?.filePath,'service.js');
  assert.equal(resolver.resolve(mod,'./service/')?.filePath,'service/entry.cjs');
  assert.equal(resolver.resolve(mod,'./service','import')?.filePath,'service.js');
  assert.equal(resolver.resolve(mod,'../escape'),undefined);
  const link=moduleResolution({modules,input:{nodeSourceInventory:['link']},tick(){},note(){}});
  assert.equal(link.resolve(mod,'./link'),undefined); // A collected symlink is metadata, never a readable module.
  assert.ok(notes.includes('NODE_COMMONJS_DIRECTORY_SOURCE_LINK'));
});
