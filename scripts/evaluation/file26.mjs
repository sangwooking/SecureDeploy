import {file26Cases} from '../../analyzers/typescript/test/file26-cases.mjs';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
export async function evaluate(root){
 const {analyze}=await import(pathToFileURL(resolve(root,'analyzers/typescript/analyzer.mjs')));
 const rows=[];
 for(const c of file26Cases){
  const runs=[analyze(c.input),analyze(c.input)];assert.deepEqual(runs[0],runs[1]);
  const r=runs[0],rule=c.track==='PATH'?'JS_FILE_PATH_INPUT_FLOW':'JS_DANGEROUS_UPLOAD_FLOW';
  const findings=r.findings.filter(f=>f.ruleId===rule&&f.confidence==='HIGH'&&f.sink.filePath===c.input.files[0].filePath);
  const uses=(r.resourceUses??[]).filter(u=>u.ruleId===rule);
  const safe=uses.some(u=>['STATIC_FILE_PATH','LEXICALLY_CONFINED_PATH'].includes(u.kind));
  let outcome=c.truth==='RISK'?(findings.length?'TP':'FN'):c.truth==='NORMAL'?(findings.length?'FP':safe?'TN':'NORMAL_DEFERRED')
   :findings.length?'UNEXPECTED_CANDIDATE':safe?'FALSE_SAFE_OBSERVATION':'UNKNOWN';
  if(c.id==='path-lookalike'&&!findings.length&&!uses.length)outcome='NORMAL_NO_FS_SINK';
  rows.push({id:c.id,track:c.track,truth:c.truth,reason:c.reason,outcome,worker:r.analyzerVersion,
   inputSha256:createHash('sha256').update(JSON.stringify(c.input)).digest('hex'),
   observations:uses.map(u=>({kind:u.kind,location:u.location,limitations:u.limitations})),
   findings:findings.map(f=>({ruleId:f.ruleId,source:f.source,sink:f.sink,flow:f.flow})),
   parsed:r.files.filter(f=>f.parseStatus==='PARSED').length,entries:r.files.reduce((sum,f)=>sum+f.entrypoints,0),
   limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort()});
 }
 const counts=track=>rows.filter(r=>r.track===track).reduce((sum,r)=>(sum[r.outcome]=(sum[r.outcome]??0)+1,sum),{});
 return {casesSha256:createHash('sha256').update(readFileSync(new URL('../../analyzers/typescript/test/file26-cases.mjs',import.meta.url))).digest('hex'),
  summary:{PATH:counts('PATH'),UPLOAD_TYPE:counts('UPLOAD_TYPE')},rows};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [baseline,output]=process.argv.slice(2);if(!baseline||!output)throw Error('TRUSTED_BASELINE_ROOT_AND_FRESH_OUTPUT_REQUIRED');
 assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:baseline,encoding:'utf8'}).trim(),'840f0601a3aee217556e92104b2c246860753ecb');
 const before=await evaluate(baseline),after=await evaluate(fileURLToPath(new URL('../../',import.meta.url)));
 const result={schemaVersion:1,baselineCommit:'840f0601a3aee217556e92104b2c246860753ecb',grade:'B_SAME_AUTHOR_NONBLIND',
  before,after,repeatIdentical:true,newOriginalApplicationTP:0,targetSourceExecuted:false,
  limitations:['Only trusted SecureDeploy analyzer modules imported; target code is parsed, never executed',
   'Known risky unsupported paths remain FN; normal without an observation remains deferred',
   'Lexical path evidence does not prove symlink, permissions, containment intent or runtime exploitability',
   'CWE-434 and CWE-400 require distinct type/execution/resource evidence, not just an upload declaration']};
 writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({before:before.summary,after:after.summary,cases:after.rows.length}));
}
