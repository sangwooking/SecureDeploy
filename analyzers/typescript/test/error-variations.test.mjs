import {test} from 'node:test';import assert from 'node:assert/strict';import {analyze} from '../analyzer.mjs';
test('later Pages error variants separate risk normal and unresolved paths',()=>{
 const cases=[['RISK',"const e=new Error('fixture');const stack=e.stack;return Response.json({detail:stack});"],
 ['RISK',"try{throw new Error('fixture')}catch(issue){const body={detail:issue.stack};return Response.json(body);}"],
 ['RISK',"return reply(new Error('fixture').stack);"],
 ['NORMAL',"console.error(new Error('fixture').stack);return new Response('generic');"],
 ['NORMAL',"Response.json(new Error('fixture').stack);return new Response('generic');"],
 ['NORMAL',"return Response.json({error:'bad request'});"],
 ['UNKNOWN',"try{external()}catch(issue){return Response.json(issue.stack);}"],
 ['UNKNOWN',"return Response.json(mask(new Error('fixture').stack));"],
 ['UNKNOWN',"if(unknownDebug())return Response.json(new Error('fixture').stack);return new Response('generic');"]];
 const counts={RISK:0,NORMAL:0,UNKNOWN:0};
 for(const [expected,body] of cases){const r=analyze({files:[{filePath:'functions/error.ts',content:`import {reply} from '../reply';export function onRequest(context){${body}}`},{filePath:'reply.ts',content:'export function reply(value){return Response.json({value});}'}]});assert.equal(r.findings.some(f=>f.ruleId==='TS_ERROR_DETAIL_EXPOSURE'),expected==='RISK',body);if(expected==='UNKNOWN')assert.ok(r.exposureUses.length);counts[expected]++;}
 console.log('TS error synthetic variants',counts,'unexpected Findings=0 missed expected candidates=0; not independent external accuracy');
});
