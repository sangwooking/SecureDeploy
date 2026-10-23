import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const run=(body,setup="const exec=require('node:child_process').exec;")=>analyze({files:[{filePath:'server.cjs',content:`const express=require('express');const app=express();${setup}app.post('/work',(req,res)=>{${body}});`}],nodeManifests:[{filePath:'package.json',express:'4.21.2'}]});
const candidate=r=>r.findings.filter(f=>f.ruleId==='JS_SHELL_COMMAND_INPUT_FLOW'&&f.confidence==='HIGH');
for(const [name,body,setup] of [
 ['direct',"exec(req.body.command);"],
 ['concat',"exec('fixed '+req.query.value);"],
 ['template','exec(`fixed ${req.params.value}`);'],
 ['alias',"const execute=exec;const value=req.body.value;execute(value);"],
 ['sync',"exec(req.body.value);","const exec=require('child_process').execSync;"],
 ['method',"cp.exec(req.body.value);","const cp=require('child_process');"],
 ['literal-shell',"exec(req.body.value,{shell:'/bin/sh'});"],
])test('shell input candidate: '+name,()=>{const r=run(body,setup);assert.equal(candidate(r).length,1);assert.equal(candidate(r)[0].kind,'CWE-78');assert.equal(candidate(r)[0].disposition,'REVIEW_REQUIRED');});
for(const [name,body,setup] of [
 ['fixed-command',"exec('fixed command');"],
 ['overwrite',"let input=req.body.value;input='constant';exec(input);"],
 ['unreachable',"return res.json({ok:true});exec(req.body.value);"],
 ['non-shell-argv',"exec('fixed',['arg',req.body.value]);","const exec=require('child_process').execFile;"],
 ['local-same-name',"exec(req.body.value);","const exec=value=>value;"],
 ['unrelated-library',"exec(req.body.value);","const exec=require('different-library').exec;"],
 ['boolean-presence',"exec(String(!!req.body.value));"],
])test('no proven shell injection: '+name,()=>assert.equal(candidate(run(body,setup)).length,0));
for(const [name,body,setup] of [
 ['unknown-transform',"exec(transform(req.body.value));"],
 ['unknown-options',"exec(req.body.value,options);"],
 ['invalid-options',"exec(req.body.value,{shell:false});"],
 ['sync-callback-not-options',"exec(req.body.value,()=>{});","const exec=require('child_process').execSync;"],
 ['mutated-module',"cp.exec=custom;cp.exec(req.body.value);","const cp=require('child_process');"],
 ['escaped-module',"alter(cp);cp.exec(req.body.value);","const cp=require('child_process');"],
 ['unsupported-shell-argv',"exec('fixed',[req.body.value],{shell:true});","const exec=require('child_process').execFile;"],
])test('uncertain process contract: '+name,()=>{const r=run(body,setup);assert.equal(candidate(r).length,0);assert.ok(r.files[0].limitations.length>0);});
test('relative helper retains the supported command path',()=>{
 const r=analyze({files:[{filePath:'server.mjs',content:"import express from 'express';import {run} from './helper.mjs';const app=express();app.post('/',(req,res)=>run(req.body.command));"},{filePath:'helper.mjs',content:"import {exec} from 'node:child_process';export function run(value){exec(value);}"}],nodeManifests:[{filePath:'package.json',express:'4.21.2'}]});assert.equal(candidate(r).length,1);
});
test('argv evidence never claims executable, argument or runtime safety',()=>{
 const normal=run("exec('fixed',['arg',req.body.value]);","const exec=require('child_process').execFile;");
 const unknown=run("exec('fixed',[req.body.value],{shell:true});","const exec=require('child_process').execFile;");
 assert.ok(normal.nodeUses.some(u=>u.kind==='ARGV_WITHOUT_SHELL_DECLARED'&&u.limitations.includes('EXECUTABLE_ARGUMENT_INJECTION_AND_PLATFORM_NOT_VERIFIED')));
 assert.ok(unknown.nodeUses.some(u=>u.kind==='PROCESS_CONTRACT_UNKNOWN'));
});
