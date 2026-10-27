import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import assert from 'node:assert/strict';
import {xss25Cases,ssrf25Cases,sqlBranch25} from '../../analyzers/typescript/test/context25-cases.mjs';

// Only import SecureDeploy's own frozen evaluator, never a benchmark project's code.
export async function evaluate(root){
 const {analyze}=await import(pathToFileURL(resolve(root,'analyzers/typescript/analyzer.mjs')));
 const {classify}=await import(pathToFileURL(resolve(root,'analyzers/typescript/url-context.mjs')));
 const rows=[];
 for(const c of [...xss25Cases,...ssrf25Cases]){
  const runs=[];
  for(let i=0;i<2;i++){
   const start=performance.now();let facts;
   if(c.id.startsWith('xss-')){
    const r=classify([{filePath:c.filePath,content:c.code}]).files[0];
    const html=c.code.includes('dangerouslySetInnerHTML');
    facts={warning:html&&!r.excludedHtmlLines?.includes(1),excluded:r.excludedHtmlLines??[],contexts:r.htmlContexts??[]};
   }else{
    const r=analyze(c.input);
    facts={warning:r.findings.some(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH'),
     destinations:r.httpUses.map(u=>u.kind),status:r.status,
     sourceSink:r.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW').map(f=>({ruleId:f.ruleId,confidence:f.confidence,source:f.source,sink:f.sink}))};
   }
   runs.push({facts,elapsedMs:Math.round((performance.now()-start)*1000)/1000});
  }
  assert.deepEqual(runs[0].facts,runs[1].facts);
  const f=runs[0].facts;
  let outcome=c.truth==='UNKNOWN'?'UNKNOWN':c.truth==='RISK'?(f.warning?'TP':'FN'):(f.warning?'FP':'TN');
  if(c.truth==='NORMAL'&&c.id.startsWith('ssrf-')&&c.id!=='ssrf-fake'&&!f.warning
     &&!f.destinations.some(k=>['FIXED_DESTINATION','ALLOWLISTED_DESTINATION'].includes(k)))outcome='NORMAL_DEFERRED';
  rows.push({id:c.id,truth:c.truth,grade:c.grade,outcome,knownGap:c.knownGap,runs});
 }
 const totals=prefix=>Object.fromEntries(['TP','FP','FN','TN','UNKNOWN','NORMAL_DEFERRED'].map(k=>[k,rows.filter(r=>r.id.startsWith(prefix)&&r.outcome===k).length]));
 const sql=analyze(sqlBranch25);
 return {xss:totals('xss-'),ssrf:totals('ssrf-'),sqlConditional:sql.nodeUses.map(u=>({ruleId:u.ruleId,kind:u.kind})),rows};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [baseline,output]=process.argv.slice(2);if(!baseline||!output)throw Error('BASELINE_CHECKOUT_AND_FRESH_OUTPUT_REQUIRED');
 const root=fileURLToPath(new URL('../../',import.meta.url));
 const result={schemaVersion:1,baselineRef:'885366254efcf73fcfd2dbfd9bb612c78060ebf0',
  casesSha256:createHash('sha256').update(readFileSync(resolve(root,'analyzers/typescript/test/context25-cases.mjs'))).digest('hex'),
  limitations:['Same-author nonblind Grade B controls; no original CVE success claimed',
   'XSS counts reconcile the existing lexical JSX rule with AST exclusions, not Source-to-DOM flow or final Backend findings',
   'DOMPurify normal assumes a supported secure version/default configuration and no unsafe hooks; engine does not verify this contract',
   'SSRF fixed/allowlisted describes URL construction only, not DNS/redirect/IP/network safety',
   'No target source execution; no runtime compatibility or whole-project safety guarantee'],
  before:await evaluate(baseline),after:await evaluate(root)};
 writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({before:{xss:result.before.xss,ssrf:result.before.ssrf},after:{xss:result.after.xss,ssrf:result.after.ssrf}}));
}
