import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {secretCases,secretInput} from './secret-flow-cases.mjs';
const leaks=r=>r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');
for(const c of secretCases)test('secret data flow: '+c.id,()=>{
 const r=analyze(c.input),fs=leaks(r),knownGap=c.id==='express-query-selected-key';
 assert.equal(fs.length,c.truth==='RISK'&&!knownGap?1:0,c.id);
 assert.equal(r.files[0].entrypoints,1);assert.equal(r.files[0].parseStatus,'PARSED');
 if(c.truth==='UNKNOWN'||knownGap)assert.ok(r.exposureUses.some(u=>['FLOW_UNRESOLVED','SENSITIVITY_UNVERIFIED'].includes(u.status))||r.files[0].limitations.some(l=>/UNRESOLVED|UNSUPPORTED|UNVERIFIED|PARTIAL/.test(l)),JSON.stringify(r.exposureUses));
 for(const f of fs){assert.equal(f.disposition,'REVIEW_REQUIRED');assert.ok(f.source.line>0&&f.sink.line>0);}
 assert.ok(!JSON.stringify(r).includes('API_SECRET'));
 assert.deepEqual(analyze(c.input),r);
});
test('secret-key shapes differ from publishable-key shapes without disclosing either literal',()=>{
 for(const [prefix,expected] of [['sb_secret_',1],['sb_publishable_',0]]){
  const canary=prefix+'A'.repeat(32),r=analyze(secretInput(`return Response.json({value:${JSON.stringify(canary)}});`));
  assert.equal(leaks(r).length,expected);assert.ok(!JSON.stringify(r).includes(canary));
 }
});
test('NextResponse and Express status responses reuse actual HTTP contracts',()=>{
 const a=analyze(secretInput("const output={status:'ok'};output.value=process.env.API_SECRET;return NextResponse.json(output);"));
 const b=analyze(secretInput("const output={status:'ok'};output.value=process.env.API_SECRET;res.status(200).json(output);",'express'));
 assert.equal(leaks(a).length,1);assert.equal(leaks(b).length,1);
});
test('public-looking Deno names and unsupported encoders are not a safe-value certificate',()=>{
 const r=analyze(secretInput("return Response.json({value:Deno.env.get('PUBLIC_CUSTOM_SECRET')});",'deno'));
 assert.equal(leaks(r).length,0);assert.ok(r.exposureUses.some(u=>u.status==='SENSITIVITY_UNVERIFIED'&&u.trace.some(t=>t.kind==='ENVIRONMENT_VALUE_UNVERIFIED')));
 assert.equal(leaks(analyze(secretInput("return Response.json({value:encodeURIComponent(process.env.API_SECRET)});"))).length,1);
 const encoded=analyze(secretInput("return Response.json({value:btoa(process.env.API_SECRET)});"));
 assert.equal(leaks(encoded).length,0);assert.ok(encoded.exposureUses.some(u=>u.status==='FLOW_UNRESOLVED'));
});
test('non-HTTP objects, nested responses and server-only values are not HTTP sinks',()=>{
 for(const body of ["const fake={json(value){return value;}};return fake.json(process.env.API_SECRET);",
  "const response=Response.json(process.env.API_SECRET);return {response};"]){assert.equal(leaks(analyze(secretInput(body))).length,0);}
});
test('property cap and cyclic object paths remain bounded and not confirmed safe',()=>{
 const body="const output={"+Array.from({length:32},(_,i)=>`f${i}:'fixed'`).join(',')+"};output.value=process.env.API_SECRET;return Response.json(output);";
 const r=analyze(secretInput(body));assert.equal(leaks(r).length,0);assert.ok(r.files[0].limitations.includes('OBJECT_DATA_PROPERTY_LIMIT'));
 const cycle=analyze(secretInput("const output={value:process.env.API_SECRET};output.self=output;return Response.json(output);"));
 assert.equal(leaks(cycle).length,0);
 assert.notEqual(analyze(secretInput(body),{maxSteps:1}).status,'COMPLETE');
});
