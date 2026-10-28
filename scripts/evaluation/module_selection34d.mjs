// SecureDeploy-owned control text only. Target programs are never executed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import {exportLinkCases} from '../../analyzers/typescript/test/export-link-fixtures.mjs';
import {continuityCases} from '../../analyzers/typescript/test/request-continuity-fixtures.mjs';

const [output,before,after]=process.argv.slice(2);
assert.ok(output&&before&&after,'OUTPUT_BEFORE_AFTER_REQUIRED');
const results={method:'PREVIOUSLY_OBSERVED_SAME_AUTHOR_GRADE_B_NOT_REAL_APP_ACCURACY',engines:{}};
for(const [expected,file] of [['ts-server-v42',before],['ts-server-v43',after]]){
 const {analyze,VERSION}=await import(pathToFileURL(file).href);
 assert.equal(VERSION,expected);
 const sets={};
 for(const [name,cases] of [['34-A',exportLinkCases.map(c=>({...c,input:{files:c.files}}))],['34-B',continuityCases]]){
  const rows=cases.map(c=>{
   const r=analyze(c.input);assert.deepEqual(r,analyze(c.input));
   const target=r.findings.filter(f=>f.ruleId===c.rule);
   return {caseId:c.id,truth:c.truth,high:target.filter(f=>f.confidence==='HIGH').length,
    medium:target.filter(f=>f.confidence==='MEDIUM').length};
  });
  sets[name]={rows,dangerous:rows.filter(r=>r.truth==='DANGEROUS').length,
   dangerousHigh:rows.filter(r=>r.truth==='DANGEROUS'&&r.high).length,
   normalWarnings:rows.filter(r=>r.truth==='NORMAL'&&(r.high||r.medium)).length,
   unknownHigh:rows.filter(r=>r.truth==='UNKNOWN'&&r.high).length};
 }
 results.engines[VERSION]=sets;
}
assert.deepEqual(results.engines['ts-server-v42'],results.engines['ts-server-v43']);
fs.writeFileSync(output,JSON.stringify(results,null,2),{flag:'wx',mode:0o600});
console.log(JSON.stringify(Object.fromEntries(Object.entries(results.engines['ts-server-v43']).map(([k,v])=>[k,
 {dangerous:v.dangerous,dangerousHigh:v.dangerousHigh,normalWarnings:v.normalWarnings,unknownHigh:v.unknownHigh}]))));
