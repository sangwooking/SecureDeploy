import {test} from 'node:test';import assert from 'node:assert/strict';import {analyze} from '../analyzer.mjs';
test('later-authored Pages variations retain risk, normal and uncertain distinctions',()=>{
 const fake='sk-'+'x'.repeat(30);const matrix=[
 ['RISK',`const value=${JSON.stringify(fake)};const alias=value;return Response.json({alias});`],
 ['RISK',"const value=context.request.headers.get('Cookie');return new Response(value);"],
 ['RISK',`console.error(${JSON.stringify(fake)});return new Response('ok');`],
 ['NORMAL',"return Response.json({token:'pk_test_public_identifier'});"],
 ['NORMAL',"return Response.json(await context.request.json());"],
 ['NORMAL',`let value=${JSON.stringify(fake)};value='[masked]';return new Response(value);`],
 ['UNKNOWN',"return Response.json(context.env.SECRET);"],
 ['UNKNOWN',`return Response.json(redact(${JSON.stringify(fake)}));`],
 ['UNKNOWN',`if(unknownGuard(context.request))return Response.json(${JSON.stringify(fake)});return new Response('ok');`],
 ];const counts={RISK:0,NORMAL:0,UNKNOWN:0};
 for(const [expected,body] of matrix){const r=analyze({files:[{filePath:'functions/check.ts',content:`export function onRequest(context){${body}}`}]});assert.equal(r.findings.some(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE'),expected==='RISK',body);if(expected==='UNKNOWN')assert.ok(r.exposureUses.length);counts[expected]++;}
 console.log('TS exposure synthetic variants',counts,'FP=0 FN=0 in labeled supported cases; not external independent accuracy');
});
