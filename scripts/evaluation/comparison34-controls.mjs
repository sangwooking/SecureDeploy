// Only SecureDeploy-owned fixtures and trusted engines. Target text is never run.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {exportLinkCases} from '../../analyzers/typescript/test/export-link-fixtures.mjs';
import {continuityCases} from '../../analyzers/typescript/test/request-continuity-fixtures.mjs';
const results={};
for(const item of process.argv.slice(3)){
 const split=item.indexOf('='),version=item.slice(0,split),file=item.slice(split+1);
 if(!['v40','v41','v42'].includes(version)||results[version])throw Error('ENGINE_ARGUMENT');
 const {analyze,VERSION}=await import(pathToFileURL(file).href);
 if(VERSION!=='ts-server-'+version)throw Error('WORKER_VERSION');
 results[version]={};
 for(const [name,cases] of [['34-A',exportLinkCases.map(c=>({...c,input:{files:c.files}}))],['34-B',continuityCases]]){
  const rows=cases.map(c=>{
   const r=analyze(c.input);assert.deepEqual(r,analyze(c.input));
   return {caseId:c.id,truth:c.truth,targetHigh:r.findings.filter(f=>f.ruleId===c.rule&&f.confidence==='HIGH').length,
    targetMedium:r.findings.filter(f=>f.ruleId===c.rule&&f.confidence==='MEDIUM').length,
    entrypoints:r.files.reduce((n,f)=>n+f.entrypoints,0),reachedFunctions:r.files.reduce((n,f)=>n+f.functionsAnalyzed,0)};
  });
  results[version][name]={method:'PREVIOUSLY_OBSERVED_SAME_AUTHOR_GRADE_B_NOT_REAL_APP_ACCURACY',
   dangerous:rows.filter(r=>r.truth==='DANGEROUS').length,normal:rows.filter(r=>r.truth==='NORMAL').length,unknown:rows.filter(r=>r.truth==='UNKNOWN').length,
   dangerousTargetHigh:rows.filter(r=>r.truth==='DANGEROUS'&&r.targetHigh).length,
   normalTargetWarnings:rows.filter(r=>r.truth==='NORMAL'&&(r.targetHigh||r.targetMedium)).length,
   unknownTargetHigh:rows.filter(r=>r.truth==='UNKNOWN'&&r.targetHigh).length,
   baselineNoFindingIsNotTN:true,rows};
 }
}
if(Object.keys(results).length!==3)throw Error('THREE_ENGINES_REQUIRED');
fs.writeFileSync(process.argv[2],JSON.stringify(results,null,2),{flag:'wx',mode:0o600});
console.log(JSON.stringify(Object.fromEntries(Object.entries(results).map(([v,sets])=>[v,Object.fromEntries(Object.entries(sets).map(([k,r])=>[k,{dangerousTargetHigh:r.dangerousTargetHigh,normalTargetWarnings:r.normalTargetWarnings,unknownTargetHigh:r.unknownTargetHigh}]))])),null,2));
