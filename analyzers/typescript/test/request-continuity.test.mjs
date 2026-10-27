import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {continuityCases} from './request-continuity-fixtures.mjs';

for(const c of continuityCases)test('request continuity: '+c.id,()=>{
 const result=analyze(c.input),high=result.findings.filter(f=>f.confidence==='HIGH');
 assert.equal(high.length,c.truth==='DANGEROUS'?1:0);
 if(c.truth==='DANGEROUS'){
  assert.equal(high[0].ruleId,c.rule);assert.equal(high[0].disposition,'REVIEW_REQUIRED');
  assert.ok(high[0].source.filePath);assert.ok(high[0].sink.filePath);
 }
 if(c.truth==='NORMAL')assert.equal(result.findings.length,0);
 if(c.truth==='UNKNOWN')assert.ok(result.files.some(f=>f.limitations.some(l=>/WRAPPER|UNRESOLVED|DEPTH/.test(l))));
 if(c.id==='fixed-fetch'||c.id==='unused-request'||c.id==='other-handler')
  assert.equal(result.httpUses[0]?.kind,'FIXED_DESTINATION');
 if(c.id==='helper-return'){
  assert.equal(high[0].source.functionName,'extract');assert.equal(high[0].sink.functionName,'GETHandler');
 }
 if(c.id==='secret-response')assert.ok(result.exposureUses.length);
});

const input=code=>({nodeManifests:[{filePath:'package.json',next:'15.2.4'}],files:[{filePath:'app/api/test/route.ts',content:code}]});
const dangerous=`async(request)=>fetch(new URL(request.url).searchParams.get('url'))`;
const wrap=`const wrap=(handler)=>async(request)=>handler(request);`;
test('multiple request bindings never share the selected handler or captured frame',()=>{
 const code=wrap+`export const GET=wrap(${dangerous});export const POST=wrap(async(request)=>fetch('https://example.invalid/fixed'));`;
 const r=analyze(input(code));assert.equal(r.findings.length,1);
 assert.equal(r.authorizationContexts.length,2);
 assert.equal(r.httpUses.filter(u=>u.kind==='FIXED_DESTINATION').length,1);
 const reversed=analyze(input(code.replace(/export const GET=(.*);export const POST=(.*);/,'export const POST=$2;export const GET=$1;')));
 assert.equal(reversed.findings.length,1);assert.equal(reversed.findings[0].sink.functionName,'GETHandler');
 assert.equal(reversed.httpUses.filter(u=>u.kind==='FIXED_DESTINATION').length,1);
});
test('factory initialization, imported mutation, generators and ambiguous bindings are not invoked',()=>{
 for(const body of [
  `export const GET=wrap(${dangerous});${wrap}`,
  `function wrap(handler){return async(request)=>handler(request);}wrap=external;export const GET=wrap(${dangerous});`,
  `const wrap=(handler)=>function*(request){return handler(request);};export const GET=wrap(${dangerous});`,
  `function wrap(handler){return async(request)=>handler(request);}function wrap(handler){return external;}export const GET=wrap(${dangerous});`,
  `const wrap=(handler)=>async(request)=>{handler=external;return handler(request);};export const GET=wrap(${dangerous});`,
  `const wrap=(handler)=>async(request)=>handler.call(this,request);export const GET=wrap(${dangerous});`,
 ])assert.equal(analyze(input(body)).findings.length,0,body);
 const files=input(`import {wrap} from '../../../lib/wrap';export const GET=wrap(${dangerous});`);
 files.files.push({filePath:'lib/wrap.ts',content:`export function wrap(handler){return async(request)=>handler(request);}wrap=external;`});
 assert.equal(analyze(files).findings.length,0);
});
test('file order, depth and step limits preserve deterministic bounded behavior',()=>{
 const c=continuityCases.find(c=>c.id==='reexported-handler');
 assert.deepEqual(analyze(c.input).findings,analyze({...c.input,files:[...c.input.files].reverse()}).findings);
 const deep=input(wrap+`export const GET=wrap(wrap(wrap(wrap(${dangerous}))));`);
 assert.equal(analyze(deep).findings.length,0);
 assert.equal(analyze(c.input,{maxSteps:20}).findings.length,0);
 assert.equal(analyze(c.input,{maxFunctions:1}).findings.length,0);
});

test('throws stop the handler and custom validators cannot validate another input',()=>{
 const stopped=input(`const wrap=(handler)=>async(request)=>{throw new Error('denied');return handler(request);};export const GET=wrap(${dangerous});`);
 assert.equal(analyze(stopped).findings.length,0);
 const checked=input(wrap+`export const GET=wrap(async(request)=>{const unused=Number(new URL(request.url).searchParams.get('first'));return fetch(new URL(request.url).searchParams.get('other'));});`);
 const r=analyze(checked);assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,1);
 assert.equal(r.findings[0].ruleId,'TS_SSRF_INPUT_FLOW');
});
