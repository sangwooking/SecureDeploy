import {createHash} from 'node:crypto';
import {analyze,VERSION} from '../../analyzers/typescript/analyzer.mjs';
import {conditionalConstructorCases} from '../../analyzers/typescript/test/conditional-constructor-fixtures.mjs';
export function evaluateConstructors(worker=analyze){
 return conditionalConstructorCases.map(c=>{
  const r=worker({files:c.files}),f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
  return {id:c.id,expectation:c.truth,sourceSha256:createHash('sha256').update(JSON.stringify(c.files)).digest('hex'),
   high:f.filter(f=>f.confidence==='HIGH').length,medium:f.filter(f=>f.confidence==='MEDIUM').length,
   entries:r.files.reduce((n,f)=>n+f.entrypoints,0),
   branches:r.nodeUses.filter(u=>u.kind.startsWith('CONSTRUCTOR_BRANCH_')).map(u=>({kind:u.kind,location:u.location,trace:u.trace})),
   limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort()};
 });
}
if(process.argv[1]?.endsWith('/constructor35.mjs'))console.log(JSON.stringify({worker:VERSION,grade:'B',independent:false,newRealTP:0,controls:evaluateConstructors()},null,2));
