// Trusted synthetic source strings only; never import or execute target code.
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {exportLinkCases} from '../../analyzers/typescript/test/export-link-fixtures.mjs';

const modulePath=process.argv[2];
if(!modulePath)throw Error('TRUSTED_ANALYZER_PATH_REQUIRED');
const {analyze,VERSION}=await import(pathToFileURL(modulePath).href);
const rows=[];
for(const fixture of exportLinkCases){
  const input={files:fixture.files};
  const result=analyze(input),repeat=analyze(input);
  // Durations are observations, not deterministic analysis evidence.
  const canonical=value=>JSON.stringify(value,(key,item)=>key==='durationMs'?undefined:item);
  assert.equal(canonical(result),canonical(repeat),'REPEAT_MISMATCH:'+fixture.id);
  const findings=result.findings.filter(f=>f.ruleId===fixture.rule&&f.confidence==='HIGH');
  rows.push({id:fixture.id,truth:fixture.truth,ruleId:fixture.rule,
    parsed:result.files.filter(f=>f.parseStatus==='PARSED').length,
    entrypoints:result.files.reduce((n,f)=>n+(f.entrypoints??0),0),
    reachedFunctions:result.files.reduce((n,f)=>n+(f.functionsAnalyzed??0),0),
    targetFindings:findings.length,
    sqlUses:result.sqlUses?.map(use=>use.kind)??[],
    limitations:[...new Set(result.files.flatMap(f=>f.limitations??[]))].sort(),
    repeatIdentical:true});
}
console.log(JSON.stringify({analyzerVersion:VERSION,grade:'B',
  method:'SAME_AUTHOR_NONBLIND_SYNTHETIC_NOT_REAL_CVE_OR_INDEPENDENT_HOLDOUT',
  normalNoFindingIsNotAutomaticallyTN:true,rows},null,2));
