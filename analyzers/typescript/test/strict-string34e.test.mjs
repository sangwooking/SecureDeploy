import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const fixed='https://example.invalid/fixed';
const input=body=>({nodeManifests:[{filePath:'package.json',next:'15.2.4','better-auth':'1.7.12'}],files:[{filePath:'app/api/task/route.ts',content:
 `import {toNextJsHandler} from 'better-auth/next-js';export const {GET}=toNextJsHandler(async request=>{let url=new URL(request.url).searchParams.get('url');${body}});`}]});
const cases=[
 ['early-not-equal',`if(url!=='${fixed}')return Response.json({ok:false});return fetch(url);`,true],
 ['positive-branch',`if(url==='${fixed}')return fetch(url);return Response.json({ok:false});`,true],
 ['literal-left',`if('${fixed}'!==url)return Response.json({ok:false});return fetch(url);`,true],
 ['parenthesized',`if((url)!==('${fixed}'))throw new Error('rejected');return fetch(url);`,true],
 ['reassigned',`if(url!=='${fixed}')return Response.json({ok:false});url=new URL(request.url).searchParams.get('other');return fetch(url);`,false],
 ['other-variable',`let other=new URL(request.url).searchParams.get('other');if(url!=='${fixed}')return Response.json({ok:false});return fetch(other);`,false],
 ['prior-alias',`const alias=url;if(url!=='${fixed}')return Response.json({ok:false});return fetch(alias);`,false],
 ['no-early-exit',`if(url!=='${fixed}'){const ignored=1;}return fetch(url);`,false],
 ['loose-comparison',`if(url!='${fixed}')return Response.json({ok:false});return fetch(url);`,false],
 ['dynamic-comparison',`const allowed=request.headers.get('allowed');if(url!==allowed)return Response.json({ok:false});return fetch(url);`,false],
 ['disjunction',`if(url==='${fixed}'||request.headers.get('bypass'))return fetch(url);return Response.json({ok:false});`,false],
 ['object-property',`const data={url};if(data.url!=='${fixed}')return Response.json({ok:false});return fetch(data.url);`,false],
 ['separate-requests',`if(request.headers.get('mode')==='safe'){if(url!=='${fixed}')return Response.json({ok:false});return fetch(url);}return fetch(url);`,false],
];
for(const [name,body,safe]of cases)test('strict string equality: '+name,()=>{
 const packet=input(body),r=analyze(packet);assert.deepEqual(r,analyze(packet));
 const warnings=r.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW');
 if(safe){
  assert.equal(warnings.length,0);
  const usage=r.httpUses.find(u=>u.kind==='FIXED_DESTINATION');assert.ok(usage,'must prove fixed, not merely drop a warning');
  assert.ok(usage.defenses.some(d=>d.kind==='STRICT_STRING_EQUALITY'));
 }else{
  assert.ok(warnings.length>0,'unproved/different/mutated values must retain review evidence');
 }
});

test('unknown closure writes invalidate exact-string evidence instead of claiming a fixed destination',()=>{
 const r=analyze(input(`if(url!=='${fixed}')return Response.json({ok:false});opaque(()=>{url=new URL(request.url).searchParams.get('other');});return fetch(url);`));
 assert.ok(r.httpUses.every(u=>u.kind!=='FIXED_DESTINATION'));
 assert.ok(r.files.some(f=>f.limitations.includes('CALLBACK_FLOW_UNSUPPORTED')));
});
