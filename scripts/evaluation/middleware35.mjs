import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {middlewareCases,input} from '../../analyzers/typescript/test/middleware-control-fixtures.mjs';

const [engine,output]=process.argv.slice(2);
if(!engine||!output)throw Error('ENGINE_AND_NEW_PRIVATE_OUTPUT_REQUIRED');
const {analyze,VERSION}=await import(pathToFileURL(engine).href);
const rows=middlewareCases.map(c=>{
  const r=analyze(input(c));
  return {id:c.id,truth:c.truth,sourceHash:createHash('sha256').update(c.code).digest('hex'),
    warnings:r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW').map(f=>({source:f.source,sink:f.sink,confidence:f.confidence})),
    entries:r.files.reduce((n,f)=>n+f.entrypoints,0),functions:r.files.reduce((n,f)=>n+f.functionsAnalyzed,0),
    observations:r.nodeUses.filter(u=>u.ruleId==='JS_SERVER_ENTRY_CONTEXT'),
    limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort()};
});
fs.writeFileSync(output,JSON.stringify({worker:VERSION,method:'AUTHORED_NONBLIND_STATIC_CONTROL_NOT_REAL_APP_TP',rows},null,2),{flag:'wx',mode:0o600});
console.log(VERSION,rows.length,'fixed controls',rows.filter(r=>r.warnings.length).length,'with target candidates');
