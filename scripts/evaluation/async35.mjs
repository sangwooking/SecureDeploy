import {createHash} from 'node:crypto';
import {analyze,VERSION} from '../../analyzers/typescript/analyzer.mjs';
import {asyncCases} from '../../analyzers/typescript/test/async-boundary-fixtures.mjs';
export function evaluateAsync(worker=analyze){return asyncCases.map(c=>{
 const r=worker({files:c.files}),f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
 return {id:c.id,expected:c.expected,sourceSha256:createHash('sha256').update(JSON.stringify(c.files)).digest('hex'),
  high:f.filter(f=>f.confidence==='HIGH').length,medium:f.filter(f=>f.confidence==='MEDIUM').length,
  states:[...new Set(r.nodeUses.filter(u=>u.operation==='BOUNDED_ASYNC_FLOW').map(u=>u.kind))].sort(),
  limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort()};
});}
if(process.argv[1]?.endsWith('/async35.mjs'))console.log(JSON.stringify({worker:VERSION,grade:'B',independent:false,newRealTP:0,cases:evaluateAsync()},null,2));
