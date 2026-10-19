import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../analyzer.mjs';
const fake='ghp_'+'a'.repeat(36);
const run=(body, helpers='')=>analyze({files:[{filePath:'worker.ts',content:helpers+'\nexport default {async fetch(request,env){'+body+'}}'}]});
const findings=r=>r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');
test('credential-shaped source flows to returned Response but never leaves metadata',()=>{
  const r=run(`const key=${JSON.stringify(fake)}; return Response.json({key});`);
  assert.equal(findings(r).length,1);assert.ok(!JSON.stringify(r).includes(fake));assert.equal(r.exposureUses[0].status,'SENSITIVE_FLOW_CANDIDATE');
});
test('logging and serialization preserve provenance, normal data and public settings do not become credentials',()=>{
  assert.equal(findings(run(`const key=${JSON.stringify(fake)};console.warn('key',key);return new Response('ok');`)).length,1);
  assert.equal(findings(run(`const key=${JSON.stringify(fake)};return new Response(JSON.stringify({key}));`)).length,1);
  for(const expression of ['env.PUBLIC_URL',"'example-public-id'",'await request.text()'])assert.equal(findings(run(`return Response.json(${expression});`)).length,0);
});
test('auth header source differs from normal echo, getenv-like names alone are insufficient',()=>{
  assert.equal(findings(run("const x=request.headers.get('Authorization');return Response.json({x});")).length,1);
  assert.equal(findings(run("const x=request.headers.get('X-Request-ID');return Response.json({x});")).length,0);
  const r=run('return Response.json(env.API_KEY);');assert.equal(findings(r).length,0);assert.equal(r.exposureUses[0].status,'SENSITIVITY_UNVERIFIED');
});
test('unused response, overwritten values and false development branch do not produce leaks',()=>{
  assert.equal(findings(run(`const k=${JSON.stringify(fake)};Response.json(k);return Response.json('ok');`)).length,0);
  assert.equal(findings(run(`let k=${JSON.stringify(fake)};k='public';return Response.json(k);`)).length,0);
  assert.equal(findings(run(`if(false)console.log(${JSON.stringify(fake)});return new Response('ok');`)).length,0);
});
test('helpers and relative import preserve data paths without executing modules',()=>{
  const helper=run(`return reply(${JSON.stringify(fake)});`,'function reply(x){return Response.json({x});}');
  assert.equal(findings(helper).length,1);assert.ok(helper.exposureUses[0].trace.some(s=>s.kind==='FUNCTION_ARGUMENT'));
  const r=analyze({files:[{filePath:'functions/x.ts',content:`import {reply} from '../lib';export function onRequest(){return reply(${JSON.stringify(fake)});}`},{filePath:'lib.ts',content:'export function reply(data){return Response.json({data});}'}]});assert.equal(findings(r).length,1);
});
test('unknown masking, custom logging, replacer and UI-only code are not confirmed exposure',()=>{
  const r=run(`const k=${JSON.stringify(fake)};return Response.json(mask(k));`);assert.equal(findings(r).length,0);assert.equal(r.exposureUses[0].status,'FLOW_UNRESOLVED');
  assert.equal(findings(run(`const console=customLogger();console.log(${JSON.stringify(fake)});return new Response('ok');`)).length,0);
  assert.equal(findings(run(`return new Response(JSON.stringify({key:${JSON.stringify(fake)}},['public']));`)).length,0);
  const ui=analyze({files:[{filePath:'src/App.tsx',content:`export function App(){console.log(${JSON.stringify(fake)});return <div/>;}`} ]});assert.equal(findings(ui).length,0);
});
