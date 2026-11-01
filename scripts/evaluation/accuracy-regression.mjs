// Compare observations, never regenerate inputs or truth from worker output.
import {createHash} from 'node:crypto';
export const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const count = (r,key) => r.coverage?.[key] ?? null;
const location = x => x && [x.filePath,x.line,x.kind].join(':');
const proven = f => f.source && f.sink && (f.flow?.length ?? 0)>0 && f.confidence==='HIGH';
export function compareCase(before,after) {
 const failures=[];const fail=x=>failures.push(x);
 if(before.id!==after.id||before.truth!==after.truth||before.inputHash!==after.inputHash)fail('INPUT_OR_ORACLE_CHANGED');
 for(const key of ['selected','parsed','entries','functions']) {
  if(count(before,key)!==null && (count(after,key)===null||count(after,key)<count(before,key)))fail('COVERAGE_LOSS_'+key.toUpperCase());
 }
 if(before.truth===null&&after.classification!=='UNKNOWN')fail('UNKNOWN_PROMOTION');
 const newUnknownReview=after.unexpectedUnknownPromotion&&!before.unexpectedUnknownPromotion;
 if(newUnknownReview&&(after.classification!=='UNKNOWN'||!after.findings.length||!after.findings.every(f=>f.disposition==='REVIEW_REQUIRED'&&proven(f))))fail('UNKNOWN_FINDING_PROMOTION');
 if(before.truth===true && !['TP','FN'].includes(after.classification))fail('VULNERABLE_CASE_ABANDONED');
 if(['TN','FP'].includes(before.classification)&&after.classification==='UNKNOWN')fail('KNOWN_NORMAL_CASE_ABANDONED');
 if(before.classification==='TP' && after.classification!=='TP')fail('TRUE_POSITIVE_LOST');
 if(before.truth===false && after.classification!=='TN' && before.classification==='TN')fail('SAFE_CASE_REGRESSION');
 if(before.classification==='FN'&&after.classification==='TP'&&!after.findings.some(proven))fail('NEW_TP_WITHOUT_FLOW_EVIDENCE');
 if(before.classification==='TP'&&after.classification==='TP')for(const f of before.findings){
  if(!after.findings.some(g=>g.ruleId===f.ruleId&&location(g.source)===location(f.source)&&location(g.sink)===location(f.sink)))fail('ESTABLISHED_SOURCE_SINK_LOST');
 }
 if(before.classification==='FP'&&after.classification==='TN'&&!(after.protections?.length))fail('FP_HIDDEN_WITHOUT_PROTECTION_EVIDENCE');
 for(const proof of before.protections??[])if(!(after.protections??[]).some(p=>location(p.location??p)===location(proof.location??proof)))fail('PROTECTION_EVIDENCE_LOST');
 return {newUnknownReviewRetainedAsUnknown:!!newUnknownReview,id:before.id,before:before.classification,after:after.classification,improved:failures.length===0&&((before.classification==='FN'&&after.classification==='TP')||(before.classification==='FP'&&after.classification==='TN')),passed:!failures.length,failures};
}
export function compareCohort(before,after) {
 const ids=new Set(before.map(x=>x.id));if(ids.size!==before.length||new Set(after.map(x=>x.id)).size!==after.length)throw Error('DUPLICATE_CASE_ID');
 if(before.length!==after.length||after.some(x=>!ids.has(x.id)))throw Error('CASE_SET_CHANGED');
 const rows=before.map(b=>compareCase(b,after.find(a=>a.id===b.id)));return {passed:rows.every(x=>x.passed),rows};
}
export function observation(c,analysis,findings=analysis.findings??[],classification) {
 const files=analysis.files??[];
 return {id:c.id,truth:c.truth,inputHash:digest(c.input??c.files??c.sourceHashes),classification:classification??(c.truth===null?'UNKNOWN':c.truth?(findings.length?'TP':'FN'):(findings.length?'FP':'TN')),unexpectedUnknownPromotion:c.unexpectedUnknownPromotion??(c.truth===null&&findings.length>0),findings,
 coverage:{selected:files.length,parsed:files.filter(f=>f.parseStatus==='PARSED').length,entries:files.reduce((n,f)=>n+(f.entrypoints??0),0),functions:files.reduce((n,f)=>n+(f.functionsAnalyzed??0),0)},
 protections:[...(analysis.sqlUses??[]),...(analysis.httpUses??[]),...(analysis.nodeUses??[]),...(analysis.authorizationContexts??[])].flatMap(n=>n.defenses??(String(n.kind).includes('ENCODED')?[n]:[])),partial:analysis.status==='PARTIAL',limitations:analysis.limitations??[]};
}
