import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {externalHandlerCases} from './external-handler34e-fixtures.mjs';
for(const c of externalHandlerCases)test('external Next adapter: '+c.id,()=>{
 const r=analyze(c.input);assert.deepEqual(r,analyze(c.input));
 assert.equal(r.files.reduce((n,f)=>n+f.entrypoints,0),c.entries);
 const high=r.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH');
 // One Sink keeps one finding even when GET and POST share it.
 assert.equal(high.length,c.truth==='FLOW'?1:0);
 if(c.truth==='NORMAL')assert.equal(r.findings.length,0);
 if(c.truth==='FLOW'){
  assert.ok(high.every(f=>f.source.filePath&&f.sink.filePath));
  assert.ok(r.nodeUses.some(u=>u.operation.startsWith('BETTER_AUTH_NEXT_')&&u.kind==='CALLBACK_BOUND'));
 }
 if(c.id==='sdk-opaque'||c.id==='sdk-callback-not-http'){
  assert.ok(r.nodeUses.some(u=>u.kind==='EXTERNAL_IMPLEMENTATION_UNKNOWN'));
  assert.equal(r.files.reduce((n,f)=>n+f.functionsAnalyzed,0),0);
 }
});

test('adapter forwards only Request and does not fabricate a route context or this receiver',()=>{
 const base=externalHandlerCases[0].input;
 const content=`import {toNextJsHandler as adapt} from 'better-auth/next-js';export const {GET}=adapt(async(request,context)=>fetch(context.params.url));`;
 const r=analyze({...base,files:[{filePath:'app/api/[url]/route.ts',content}]});
 assert.equal(r.files[0].entrypoints,1);
 assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,0);
 const contextual=analyze({...base,files:[{filePath:'app/api/[url]/route.ts',content:`import {toNextJsHandler as adapt} from 'better-auth/next-js';export const {GET}=adapt({handler:async function(request){return fetch(this.url)}});`}]});
 assert.ok(contextual.nodeUses.some(u=>u.kind==='EXTERNAL_IMPLEMENTATION_UNKNOWN'));
 assert.equal(contextual.findings.length,0);
});

test('uninspected config scope and alias overrides cannot establish a package adapter origin',()=>{
 const base=externalHandlerCases[0].input;
 const incomplete=analyze({...base,typescriptConfigs:[],nodeSourceInventoryComplete:false,nodeEnumeratedDirectories:[]});
 assert.equal(incomplete.files[0].entrypoints,0);
 const alias=analyze({...base,typescriptConfigs:[{filePath:'tsconfig.json',status:'SELECTED',content:'{"compilerOptions":{"paths":{"better-auth/*":["./vendor/*"]}}}'}]});
 assert.equal(alias.files[0].entrypoints,0);
 assert.equal(alias.findings.length,0);
});

test('only audited declared adapter floors link; installed SDK and auth success remain unverified',()=>{
 const base=externalHandlerCases[0].input;
 for(const version of ['1.6.23','^1.6.23','1.7.12','~1.7.12']){
  const r=analyze({...base,nodeManifests:[{filePath:'package.json',next:'15.2.4','better-auth':version}]});
  assert.equal(r.files[0].entrypoints,1);
  assert.ok(r.nodeUses.some(u=>u.limitations.includes('DECLARED_VERSION_NOT_INSTALLED_LIBRARY')));
  assert.ok(r.authorizationContexts.every(c=>c.conclusion==='NOT_VERIFIED'));
 }
 for(const version of ['1.6.24','^1.8.0','workspace:*']){
  const r=analyze({...base,nodeManifests:[{filePath:'package.json',next:'15.2.4','better-auth':version}]});
  assert.equal(r.files[0].entrypoints,0);assert.equal(r.findings.length,0);
 }
});
