// Run a trusted analyzer against frozen synthetic text; no target imports/execution.
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {continuityCases} from '../../analyzers/typescript/test/request-continuity-fixtures.mjs';
const {analyze,VERSION}=await import(pathToFileURL(process.argv[2]).href);
const rows=continuityCases.map(c=>{
 const result=analyze(c.input);assert.deepEqual(result,analyze(c.input),'NONDETERMINISTIC:'+c.id);
 return {id:c.id,truth:c.truth,ruleId:c.rule,entrypoints:result.files.reduce((n,f)=>n+f.entrypoints,0),
  reachedFunctions:result.files.reduce((n,f)=>n+f.functionsAnalyzed,0),
  targetHigh:result.findings.filter(f=>f.ruleId===c.rule&&f.confidence==='HIGH').length,
  unresolvedCandidates:result.findings.filter(f=>f.confidence==='MEDIUM').length,
  httpUses:result.httpUses.map(u=>u.kind),
  wrapperBindings:result.nodeUses.filter(u=>u.operation==='STATIC_NEXT_WRAPPER_BINDING').length,
  limitations:[...new Set(result.files.flatMap(f=>f.limitations))].sort(),repeatIdentical:true};
});
console.log(JSON.stringify({version:VERSION,method:'SAME_AUTHOR_NONBLIND_GRADE_B',
 baselineNoFindingIsNotTN:true,newRealCveTP:0,independentHoldout:0,rows},null,2));
