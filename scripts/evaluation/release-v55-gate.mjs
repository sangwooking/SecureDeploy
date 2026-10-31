// Read-only release gate: replay unchanged oracles and check integrated ancestry.
// No provider, database, registry, source upload or deployment is performed here.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';

const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const output=process.argv[2];
if(!output)throw Error('Usage: node scripts/evaluation/release-v55-gate.mjs OUTPUT_DIRECTORY');
fs.mkdirSync(output,{recursive:true});
const git=(...args)=>execFileSync('git',['-C',repo,...args],{encoding:'utf8'}).trim();
const ancestors=['7b36576','a493585','fb960bc','4909884','39a26a9','0050ef7','b7189c7','8270d80','b284cc7','0f294f4'];
for(const sha of ancestors)execFileSync('git',['-C',repo,'merge-base','--is-ancestor',sha,'HEAD']);
const frozen=['epic01-dplus-inputs.mjs','epic01-dplus-evaluate.mjs','worker-v53-inputs.mjs','worker-v53-evaluate.mjs','worker-v54-inputs.mjs','worker-v54-evaluate.mjs','worker-v55-inputs.mjs','worker-v55-evaluate.mjs','epic01-dplus-python.py','worker-v54-python.py'];
const hashes=frozen.map(name=>{
  const file='scripts/evaluation/'+name,bytes=fs.readFileSync(path.join(repo,file));
  assert.ok(bytes.equals(execFileSync('git',['-C',repo,'show','0f294f4:'+file])),file+' changed');
  return {file,sha256:createHash('sha256').update(bytes).digest('hex')};
});
const worker=path.join(repo,'analyzers/typescript/analyzer.mjs');
const jobs=[
 ['TS33','epic01-dplus-evaluate.mjs',{TP:16,FP:0,TN:5,FN:0,UNKNOWN:12}],
 ['TS22','worker-v53-evaluate.mjs',{TP:8,FP:0,TN:6,FN:0,UNKNOWN:8}],
 ['HTML20','worker-v54-evaluate.mjs',{TP:2,FP:0,TN:5,FN:6,UNKNOWN:7}],
 ['HTML23','worker-v55-evaluate.mjs',{TP:7,FP:0,TN:7,FN:1,UNKNOWN:8}],
 ['PY5','epic01-dplus-python.py',{TP:2,FP:0,TN:2,FN:1,UNKNOWN:0}],
 ['PY12','worker-v54-python.py',{TP:1,FP:0,TN:5,FN:0,UNKNOWN:6}],
];
const results=[];
for(const [name,script,expected] of jobs){
 const target=path.resolve(output,name+'.json'),python=script.endsWith('.py');
 execFileSync(python?'python3':process.execPath,[path.join(repo,'scripts/evaluation',script),python?path.join(repo,'analyzers/python/worker.py'):worker,target],{cwd:repo,timeout:60000});
 const result=JSON.parse(fs.readFileSync(target));assert.deepEqual(result.counts,expected,name);
 results.push({name,counts:result.counts});
}
fs.writeFileSync(path.join(output,'FROZEN_RELEASE_GATE.json'),JSON.stringify({sha:git('rev-parse','HEAD'),ancestors,hashes,results,passed:true,scope:'Separate synthetic cohorts; not whole-project accuracy. No oracle edits.'},null,2));
console.log('RELEASE_V55_FROZEN_GATE_PASS');
