import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {exportLinkCases} from './export-link-fixtures.mjs';

for(const item of exportLinkCases)test(`bounded export linking: ${item.id}`,()=>{
  const result=analyze({files:item.files});
  const findings=result.findings.filter(f=>f.ruleId===item.rule&&f.confidence==='HIGH');
  assert.equal(findings.length,item.truth==='DANGEROUS'?1:0);
  if(item.truth==='DANGEROUS'){
    assert.equal(findings[0].sink.filePath,'service'+(item.id.startsWith('express')?'.mjs':'.ts'));
    assert.equal(findings[0].disposition,'REVIEW_REQUIRED');
    if(item.id==='express-handler-export')assert.ok(result.authorizationContexts.some(c=>c.entry.kind==='EXPRESS_HANDLER'));
    else assert.ok(findings[0].source.filePath!==findings[0].sink.filePath);
  }
  if(item.id==='bound-value')assert.ok(result.sqlUses.some(x=>x.kind==='PARAMETERIZED_QUERY'&&x.executionObserved));
  if(item.truth==='UNKNOWN')assert.ok(result.files.some(f=>f.limitations.some(x=>/MODULE_EXPORT|WILDCARD|CALL_TARGET|CONTEXT_MISSING/.test(x))));
});

test('forwarding keeps binding and request state independent of supplied file order',()=>{
  const key=r=>r.findings.map(f=>JSON.stringify(f)).sort();
  for(const item of exportLinkCases){
    assert.deepEqual(key(analyze({files:item.files})),key(analyze({files:[...item.files].reverse()})),item.id);
  }
});

test('missing selected preferred source never falls through to another extension',()=>{
  const result=analyze({files:[
    {filePath:'worker.ts',content:`import {query} from './service';export default {fetch(request,env){return query(env.DB,new URL(request.url).searchParams.get('q'));}}`},
    {filePath:'service.ts',content:`export function query( {`},
    {filePath:'service.js',content:`export function query(db,q){return db.prepare(q).run();}`},
  ]});
  assert.equal(result.findings.length,0);
  assert.ok(result.files.some(f=>f.limitations.includes('MODULE_EXPORT_TARGET_NOT_INSPECTED')));
});

test('mutation, duplicate exports and unresolved aliases cannot retain a function target',()=>{
  const main={filePath:'worker.ts',content:`import {query} from './service';export default {fetch(request,env){return query(env.DB,new URL(request.url).searchParams.get('q'));}}`};
  for(const body of [
    `function query(db,q){return db.prepare(q).run();}query++;export {query};`,
    `const run=(db,q)=>db.prepare(q).run();const query=run;export {query};`,
    `function query(db,q){return db.prepare(q).run();}export {query,query};`,
    `let query=(db,q)=>db.prepare(q).run();export {query};`,
  ])assert.equal(analyze({files:[main,{filePath:'service.ts',content:body}]}).findings.length,0);
});

test('Node forwarding stays pure, format-aware and never adopts CommonJS directory fallback',()=>{
  const boot={filePath:'boot.mjs',content:`import express from 'express';import {handler} from './api.mjs';const app=express();app.get('/',handler);`};
  const service={filePath:'service.mjs',content:`import {exec} from 'node:child_process';export function handler(req,res){exec(req.query.command);}`};
  const high=r=>r.findings.filter(f=>f.ruleId==='JS_SHELL_COMMAND_INPUT_FLOW'&&f.confidence==='HIGH').length;
  assert.equal(high(analyze({files:[boot,{filePath:'api.mjs',content:`export {handler} from './service.mjs';`},service]})),1);
  for(const code of [
    `export {handler} from './service';`,
    `unknownInitialization();export {handler} from './service.mjs';`,
    `module.exports={};export {handler} from './service.mjs';`,
    `export type {handler} from './service.mjs';`,
    `export * from './service.mjs';`,
  ])assert.equal(high(analyze({files:[boot,{filePath:'api.mjs',content:code},service]})),0,code);
});

test('export cycles and large plans remain charged to existing depth and step budgets',()=>{
  const item=exportLinkCases.find(c=>c.id==='named-barrel-alias');
  const deep=item.files.map(f=>f.filePath==='api.ts'?{...f,content:`export {query} from './middle';`}:f);
  deep.push({filePath:'middle.ts',content:`export {query} from './service';`});
  assert.equal(analyze({files:deep},{maxDepth:1}).findings.length,0);
  const limited=analyze({files:item.files},{maxSteps:15});
  assert.equal(limited.findings.length,0);assert.equal(limited.status,'PARTIAL');
  assert.ok(limited.files.some(f=>f.limitations.some(x=>/BUDGET|LIMIT/.test(x))));
});
