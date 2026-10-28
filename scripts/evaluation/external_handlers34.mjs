// Owned static controls only. These results are not real-app vulnerability accuracy.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {externalHandlerCases} from '../../analyzers/typescript/test/external-handler34e-fixtures.mjs';
import {exportLinkCases} from '../../analyzers/typescript/test/export-link-fixtures.mjs';
import {continuityCases} from '../../analyzers/typescript/test/request-continuity-fixtures.mjs';
const [output,before,after]=process.argv.slice(2);
assert.ok(output&&before&&after);
const negativeContractControls=new Set(['same-name-local','different-package','not-exported']);
const report={method:'SAME_AUTHOR_NONBLIND_GRADE_B_STATIC_FLOW_NOT_EXPLOIT_PROOF',
 truthScope:'TARGET_ADAPTER_CONTRACT_NOT_WHOLE_PROJECT_SAFETY',
 negativeContractControls:[...negativeContractControls],engines:{}};
for(const [version,file]of [['ts-server-v43',before],['ts-server-v44',after]]){
 const {analyze,VERSION}=await import(pathToFileURL(file).href);assert.equal(VERSION,version);
 report.engines[version]={};
 for(const [name,cases]of [['34-E',externalHandlerCases],['34-A',exportLinkCases.map(c=>({...c,input:{files:c.files}}))],['34-B',continuityCases]]){
  report.engines[version][name]=cases.map(c=>{
   const r=analyze(c.input);assert.deepEqual(r,analyze(c.input));
   const findings=r.findings.filter(f=>f.ruleId===(c.rule??'TS_SSRF_INPUT_FLOW'));
   return {id:c.id,truth:c.truth,entries:r.files.reduce((n,f)=>n+f.entrypoints,0),
    functions:r.files.reduce((n,f)=>n+f.functionsAnalyzed,0),high:findings.filter(f=>f.confidence==='HIGH').length,
    medium:findings.filter(f=>f.confidence==='MEDIUM').length,opaque:r.nodeUses.filter(u=>u.operation.startsWith('BETTER_AUTH_NEXT_')&&u.kind==='EXTERNAL_IMPLEMENTATION_UNKNOWN').length};
  });
 }
}
for(const set of ['34-A','34-B'])assert.deepEqual(report.engines['ts-server-v43'][set],report.engines['ts-server-v44'][set]);
fs.writeFileSync(output,JSON.stringify(report,null,2),{flag:'wx',mode:0o600});
for(const [v,sets]of Object.entries(report.engines))console.log(v,Object.fromEntries(Object.entries(sets).map(([k,rows])=>[k,
 {cases:rows.length,highCases:rows.filter(r=>r.high).length,
  normalFlowWarnings:rows.filter(r=>r.truth==='NORMAL'&&!negativeContractControls.has(r.id)&&(r.high||r.medium)).length,
  negativeContractControls:rows.filter(r=>negativeContractControls.has(r.id)).length,
  opaqueCases:rows.filter(r=>r.opaque).length}])));
