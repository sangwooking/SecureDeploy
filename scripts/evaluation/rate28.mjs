import {rate28Cases} from '../../analyzers/typescript/test/rate28-cases.mjs';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
export async function evaluate(root){
 const {analyze}=await import(pathToFileURL(resolve(root,'analyzers/typescript/analyzer.mjs')));
 const rows=[];
 for(const c of rate28Cases){
  const r=analyze(c.input);assert.deepEqual(r,analyze(c.input));
  const findings=r.findings.filter(f=>f.ruleId==='JS_RATE_LIMIT_BYPASS_REVIEW'&&f.confidence==='HIGH');
  const uses=r.nodeUses.filter(u=>u.ruleId==='JS_RATE_LIMIT_CONTEXT'||u.ruleId==='JS_RATE_LIMIT_BYPASS_REVIEW');
  const normal=uses.some(u=>['RATE_LIMIT_DEFAULT_STOP_BOUND','RATE_LIMIT_ZERO_BLOCKS_BOUND'].includes(u.kind));
  const outcome=c.truth==='RISK'?(findings.length?'TP':'FN'):c.truth==='NORMAL'?(findings.length?'FP':normal?'TN':'NORMAL_DEFERRED')
   :findings.length?'UNEXPECTED_CANDIDATE':'UNKNOWN';
  rows.push({id:c.id,truth:c.truth,reason:c.reason,outcome,worker:r.analyzerVersion,
   inputSha256:createHash('sha256').update(JSON.stringify(c.input)).digest('hex'),findings,uses,
   limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort()});
 }
 return {casesSha256:createHash('sha256').update(readFileSync(new URL('../../analyzers/typescript/test/rate28-cases.mjs',import.meta.url))).digest('hex'),
  summary:rows.reduce((a,r)=>(a[r.outcome]=(a[r.outcome]??0)+1,a),{}),rows};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [baseline,output]=process.argv.slice(2);if(!baseline||!output)throw Error('BASELINE_AND_FRESH_OUTPUT_REQUIRED');
 const before=await evaluate(baseline),after=await evaluate(fileURLToPath(new URL('../../',import.meta.url)));
 writeFileSync(output,JSON.stringify({schemaVersion:1,baselineCommit:'c9fb56a2d9b1db008dd6c4c169a7296e197ebef3',before,after,
  repeatIdentical:true,independentReview:false,newOriginalTP:0,targetExecuted:false},null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({cases:after.rows.length,before:before.summary,after:after.summary}));
}
