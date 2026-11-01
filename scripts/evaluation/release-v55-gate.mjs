// Read-only release gate: replay unchanged oracles and check integrated ancestry.
// No provider, database, registry, source upload or deployment is performed here.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';

const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const output=process.argv[2],baseline=process.argv[3];
if(!output||!baseline)throw Error('Usage: node scripts/evaluation/release-v55-gate.mjs OUTPUT_DIRECTORY BASELINE_ROOT');
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
// Historical aggregate expectations identify only the v58/v11 baseline. Candidate
// acceptance is case-by-case; immutable oracles/evaluators above are not rewritten.
const {compareCohort,observation}=await import('./accuracy-regression.mjs');
const {pathToFileURL}=await import('node:url');
const jobs=[
 ['TS33','epic01-dplus', {TP:16,FP:0,TN:5,FN:0,UNKNOWN:12}],
 ['TS22','worker-v53',{TP:8,FP:0,TN:6,FN:0,UNKNOWN:8}],
 ['HTML20','worker-v54',{TP:2,FP:0,TN:5,FN:6,UNKNOWN:7}],
 ['HTML23','worker-v55',{TP:7,FP:0,TN:7,FN:1,UNKNOWN:8}],
 ['PY5','epic01-dplus-python',{TP:2,FP:0,TN:2,FN:1,UNKNOWN:0}],
 ['PY12','worker-v54-python',{TP:1,FP:0,TN:5,FN:0,UNKNOWN:6}],
];
const results=[];
for(const [name,stem,historical]of jobs){
 const python=name.startsWith('PY'),versions=[];
 for(const [label,root]of [['baseline',baseline],['candidate',repo]]){
  const script=python?stem+'.py':stem+'-evaluate.mjs',target=path.resolve(output,name+'-'+label+'.json');
  execFileSync(python?'python3':process.execPath,[path.join(repo,'scripts/evaluation',script),path.join(root,python?'analyzers/python/worker.py':'analyzers/typescript/analyzer.mjs'),target],{cwd:repo,timeout:60000});
  const raw=JSON.parse(fs.readFileSync(target));if(label==='baseline')assert.deepEqual(raw.counts,historical,name+' baseline changed');
  let normalized;
  if(python)normalized=raw.rows.map((r,i)=>observation({...r,id:r.id??String(i)},r.analysis,r.analysis.findings.filter(f=>name==='PY5'?r.id.startsWith('django-')?f.ruleId.includes('SQL'):f.ruleId.startsWith('PY_AUTHORIZATION'):f.ruleId.startsWith('PY_AUTHORIZATION')),r.classification));
  else{
   const{cases}=await import('./'+stem+'-inputs.mjs');const{evaluatePipeline}=await import(pathToFileURL(path.join(root,'analyzers/typescript/analyzer.mjs')));
   normalized=cases.map(c=>{const a=evaluatePipeline(c.input).analysis,r=(raw.rows??raw.results).find(r=>r.id===c.id);return observation(c,a,a.findings.filter(f=>f.ruleId===(c.rule??'HTTP_HTML_INPUT_FLOW')),r.classification);});
  }
  fs.writeFileSync(path.resolve(output,name+'-'+label+'-observations.json'),JSON.stringify(normalized,null,2));versions.push({label,counts:raw.counts,partial:raw.partial,rows:normalized});
 }
 const comparison=compareCohort(versions[0].rows,versions[1].rows);results.push({name,versions,comparison});
}
const passed=results.every(r=>r.comparison.passed);
fs.writeFileSync(path.join(output,'FROZEN_RELEASE_GATE.json'),JSON.stringify({sha:git('rev-parse','HEAD'),baselineWorkerHashes:Object.fromEntries(['typescript/analyzer.mjs','python/worker.py'].map(f=>[f,createHash('sha256').update(fs.readFileSync(path.join(baseline,'analyzers',f))).digest('hex')])),ancestors,hashes,results,passed,scope:'Independent engines, identical frozen inputs and truth. Not general real-world accuracy.'},null,2));
if(!passed){console.error('CASE_REGRESSION_DETECTED');process.exitCode=1;}else console.log('FROZEN_CASE_REGRESSION_GATE_PASS');
