import ts from 'typescript';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {tsPaths} from '../ts-paths.mjs';
import {analyze} from '../analyzer.mjs';
import {moduleSelectionCases,defaultModuleConfig} from './module-selection34d-fixtures.mjs';
for(const c of moduleSelectionCases)test('typed source alias: '+c.id,()=>{
 const mod={filePath:'src/app/api/route.ts'},notes=[];
 const r=tsPaths({ts,input:{typescriptConfigs:c.configs??[defaultModuleConfig],nodeSourceInventory:c.inventory,nodeEnumeratedDirectories:c.directories??[]},
  modules:new Map(c.files.map(filePath=>[filePath,{filePath}])),charge(){},note(m,n){notes.push(n);}});
 assert.equal(r.target(mod,c.specifier??'@/lib/item')?.filePath??null,c.expected);
 if(!c.expected)assert.ok(notes.length);
});
test('typed alias resolves the intended service and preserves risk, fixed destinations and missing sources',()=>{
 const input={nodeManifests:[{filePath:'package.json',next:'15.2.4'}],typescriptConfigs:[defaultModuleConfig],
  nodeSourceInventory:['src/lib/item','src/lib/item/index.ts'],nodeEnumeratedDirectories:['src/lib/item'],
  files:[{filePath:'src/app/api/route.ts',content:`import {run} from '@/lib/item';export async function GET(request){return run(new URL(request.url).searchParams.get('url'));}`},
   {filePath:'src/lib/item/index.ts',content:`export {run} from './service';`},
   {filePath:'src/lib/item/service.ts',content:`export function run(value){return fetch(value);}`} ]};
 assert.equal(analyze(input).findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH').length,1);
 const safe={...input,files:input.files.map(f=>f.filePath.endsWith('service.ts')?{...f,content:`export function run(value){return fetch('https://example.invalid/fixed');}`}:f)};
 assert.equal(analyze(safe).findings.length,0);
 const missing={...input,files:[input.files[0]]};assert.equal(analyze(missing).findings.length,0);
 assert.deepEqual(analyze(input).findings,analyze({...input,files:[...input.files].reverse()}).findings);
});
test('relative bundled imports skip directories and select files before index without adopting Node runtime rules',()=>{
 const route={filePath:'worker.ts',content:`import {run} from './lib';export default{fetch(request){return run(new URL(request.url).searchParams.get('url'));}}`};
 const lib={filePath:'lib/index.ts',content:`export function run(value){return fetch(value);}`};
 const base={files:[route,lib],nodeSourceInventory:['lib','lib/index.ts'],nodeEnumeratedDirectories:['lib'],typescriptConfigs:[defaultModuleConfig]};
 assert.equal(analyze(base).findings.length,1);
 const preferred={filePath:'lib.ts',content:`export function run(value){return fetch('https://example.invalid/fixed');}`};
 assert.equal(analyze({...base,files:[route,lib,preferred],nodeSourceInventory:[...base.nodeSourceInventory,'lib.ts']}).findings.length,0);
 const missing={...base,nodeSourceInventory:[...base.nodeSourceInventory,'lib.ts']};
 assert.equal(analyze(missing).findings.length,0);
});
