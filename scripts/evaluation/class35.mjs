import {createHash} from 'node:crypto';
import {analyze,VERSION} from '../../analyzers/typescript/analyzer.mjs';
import {classCases} from '../../analyzers/typescript/test/class-bootstrap-fixtures.mjs';

// Same-author, nonblind Grade B controls. Not an estimate of real-app accuracy.
export function evaluateClasses(worker=analyze){
  return classCases.map(c=>{
    const r=worker({files:c.files});
    const warnings=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
    return {id:c.id,truth:c.truth,sourceSha256:createHash('sha256').update(JSON.stringify(c.files)).digest('hex'),
      targetFindings:warnings.length,high:warnings.filter(f=>f.confidence==='HIGH').length,
      entries:r.files.reduce((n,f)=>n+f.entrypoints,0),
      classLinks:r.nodeUses.filter(u=>['CLASS_CONSTRUCTED','CONSTRUCTOR_ARGUMENT_CONNECTED','METHOD_CALL_CONNECTED'].includes(u.kind)).map(u=>u.kind),
      limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort()};
  });
}
export function summarize(rows,worker=VERSION){
  return {worker,grade:'B',independent:false,blind:false,realAppTP:0,
    risk:rows.filter(c=>c.truth==='RISK').length,
    supportedRiskDetected:rows.filter(c=>c.truth==='RISK'&&c.targetFindings===1&&c.high===1).length,
    normal:rows.filter(c=>c.truth==='NORMAL').length,
    normalWarnings:rows.filter(c=>c.truth==='NORMAL').reduce((n,c)=>n+c.targetFindings,0),
    noEntry:rows.filter(c=>c.truth==='NO_ENTRY').length,
    unknown:rows.filter(c=>c.truth==='UNKNOWN').length,cases:rows};
}
if(process.argv[1]?.endsWith('/class35.mjs'))console.log(JSON.stringify(summarize(evaluateClasses()),null,2));
