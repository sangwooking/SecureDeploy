import {test} from 'node:test';import assert from 'node:assert/strict';import {analyze} from '../analyzer.mjs';
const run=body=>analyze({files:[{filePath:'worker.ts',content:'export default {fetch(request,env){'+body+'}}'}]});
const errors=r=>r.findings.filter(f=>f.ruleId==='TS_ERROR_DETAIL_EXPOSURE');
test('known Error stack must reach a returned response, not only log or unused object',()=>{
 assert.equal(errors(run("const e=new Error('fixture');return Response.json({stack:e.stack});")).length,1);
 for(const body of ["console.error(new Error('fixture').stack);return new Response('ok');","Response.json(new Error('fixture').stack);return new Response('ok');","return Response.json({error:'invalid request'});"])assert.equal(errors(run(body)).length,0);
});
test('only bounded known throw catch confirms the stack type and return flow',()=>{
 assert.equal(errors(run("try{throw new Error('fixture')}catch(e){return Response.json({error:e.stack});}")).length,1);
 const r=run("try{external()}catch(e){return Response.json({error:e.stack});}");assert.equal(errors(r).length,0);assert.ok(r.exposureUses.some(u=>u.status==='FLOW_UNRESOLVED'));
});
test('unknown mask, reassignment, debug branch and plain stack fields do not create findings',()=>{
 for(const body of ["return Response.json(mask(new Error('fixture').stack));","let e=new Error('fixture');e={stack:'generic'};return Response.json(e.stack);","const e=new Error('fixture');maskObject(e);return Response.json(e.stack);","const e=new Error('fixture');e.stack='generic';return Response.json(e.stack);","if(unknownDebug())return Response.json(new Error('fixture').stack);return new Response('ok');","return Response.json({stack:'public value'});"])assert.equal(errors(run(body)).length,0,body);
});
test('fetch without signal is not classified as disabled timeout or a service failure',()=>{
 const r=run("return fetch('https://fixture.invalid');");assert.equal(r.findings.length,0);
});
test('empty catch is partial support rather than a worker exception',()=>{
 const r=run("try{throw new Error('fixture')}catch(e){}return new Response('ok');");assert.equal(errors(r).length,0);assert.ok(!r.files[0].limitations.includes('ANALYSIS_BUDGET_EXCEEDED'));
});
test('error messages containing credential-shaped data retain sensitive log provenance without duplicating HTTP error findings',()=>{
 const fake='ghp_'+'a'.repeat(36);const r=run(`console.error(new Error(${JSON.stringify(fake)}).stack);return new Response('ok');`);
 assert.equal(r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE').length,1);assert.equal(errors(r).length,0);assert.ok(!JSON.stringify(r).includes(fake));
});
