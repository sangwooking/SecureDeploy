import {web27Cases} from '../../analyzers/typescript/test/web27-cases.mjs';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const rules={CORS:'JS_CORS_CREDENTIAL_REFLECTION',COOKIE:'JS_SESSION_COOKIE_ATTRIBUTE_REVIEW',CSRF:'JS_CSRF_INPUT_FLOW'};
export async function evaluate(root){
 const {analyze}=await import(pathToFileURL(resolve(root,'analyzers/typescript/analyzer.mjs')));
 const rows=[];
 for(const c of web27Cases){
  const r=analyze(c.input);assert.deepEqual(r,analyze(c.input));
  const hits=r.findings.filter(f=>f.ruleId===rules[c.track]&&f.confidence==='HIGH'&&f.sink.filePath===c.input.files[0].filePath);
  const observations=r.nodeUses.filter(u=>u.ruleId===rules[c.track]||u.ruleId==='JS_WEB_SECURITY_CONTEXT');
  const normal=c.track==='CORS'?observations.some(u=>['CORS_FIXED_ORIGIN','CORS_WILDCARD_DECLARED','CORS_WILDCARD_CREDENTIALS_BLOCKED','CORS_POLICY_NOT_APPLICABLE'].includes(u.kind))
   :c.track==='COOKIE'?observations.some(u=>u.kind==='SESSION_COOKIE_ATTRIBUTES'&&u.limitations.includes('COOKIE_SECURE_ENABLED')&&u.limitations.some(s=>['COOKIE_HTTPONLY_ENABLED','COOKIE_HTTPONLY_DEFAULT_ENABLED'].includes(s)))
   :observations.some(u=>['CSRF_READ_ONLY_LOCAL_BODY','CSRF_EXACT_ORIGIN_CONSTRAINT'].includes(u.kind));
  const outcome=c.truth==='RISK'?(hits.length?'TP':'FN'):c.truth==='NORMAL'?(hits.length?'FP':normal?'TN':'NORMAL_DEFERRED')
   :hits.length?'UNEXPECTED_CANDIDATE':'UNKNOWN';
  rows.push({id:c.id,track:c.track,truth:c.truth,reason:c.reason,outcome,worker:r.analyzerVersion,
   inputSha256:createHash('sha256').update(JSON.stringify(c.input)).digest('hex'),observations,
   findings:hits,limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort()});
 }
 return {casesSha256:createHash('sha256').update(readFileSync(new URL('../../analyzers/typescript/test/web27-cases.mjs',import.meta.url))).digest('hex'),
  summary:Object.fromEntries(Object.keys(rules).map(t=>[t,rows.filter(r=>r.track===t).reduce((s,r)=>(s[r.outcome]=(s[r.outcome]??0)+1,s),{})])),rows};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [baseline,output]=process.argv.slice(2);if(!baseline||!output)throw Error('TRUSTED_BASELINE_AND_FRESH_OUTPUT_REQUIRED');
 const before=await evaluate(baseline),after=await evaluate(fileURLToPath(new URL('../../',import.meta.url)));
 writeFileSync(output,JSON.stringify({schemaVersion:1,baselineCommit:'f2767e06457e63cb2798df27b8829a88c368d925',before,after,
  repeatIdentical:true,independentReview:false,newOriginalTP:0,targetExecuted:false},null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({cases:after.rows.length,before:before.summary,after:after.summary}));
}
