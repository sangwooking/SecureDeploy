import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const run=body=>analyze({files:[{filePath:'api.cjs',content:`const app=require('express')();const launch=require('child_process').exec;app.post('/render',(req,res)=>{${body}});`}],nodeManifests:[{filePath:'package.json',express:'4.21.2'}]});
const count=r=>r.findings.filter(f=>f.ruleId==='JS_SHELL_COMMAND_INPUT_FLOW'&&f.confidence==='HIGH').length;
for(const [name,body] of [
 ['repeat-match',`const text=req.body.document;const pattern=/asset=(https?:.*)/;if(typeof text==='string'&&text.match(pattern)){const link=text.match(pattern)[1];launch('convert '+link);}`],
 ['match-variable',`const text=req.query.url;const m=text.match(/(.*)/);if(m){launch('convert '+m[1]);}`],
 ['exec-null-guard',`const text=req.query.url;const m=/(.*)/.exec(text);if(m!==null){launch('convert '+m[1]);}`],
 ['early-return',`const text=req.query.url;const m=text.match(/(.*)/);if(!m)return;launch('convert '+m[1]);`],
])test('regex capture retains shell source: '+name,()=>{const r=run(body);assert.equal(count(r),1,JSON.stringify(r.nodeUses));assert.ok(r.findings.find(f=>f.ruleId==='JS_SHELL_COMMAND_INPUT_FLOW').flow.some(p=>p.kind==='REGEX_CAPTURE'));});
for(const [name,body] of [
 ['overwrite',`const m=req.query.url.match(/(.*)/);if(m){let link=m[1];link='fixed';launch('convert '+link);}`],
 ['restricted-token',`const m=req.query.url.match(/^([A-Za-z0-9_]+)$/);if(m)launch('convert '+m[1]);`],
 ['fixed-input',`const m='static'.match(/(.*)/);if(m)launch('convert '+m[1]);`],
 ['fixed-capture',`const m=req.query.url.match(/^(fixed)$/);if(m)launch(m[1]);`],
 ['no-null-check',`launch(req.query.url.match(/(.*)/)[1]);`],
 ['global-match',`const m=req.query.url.match(/(.*)/g);if(m)launch(m[1]);`],
 ['dynamic-pattern',`const m=req.query.url.match(new RegExp(req.query.pattern));if(m)launch(m[1]);`],
 ['optional-capture',`const m=req.query.url.match(/(.*)?/);if(m)launch(m[1]);`],
 ['unknown-transform',`const m=req.query.url.match(/(.*)/);if(m)launch(clean(m[1]));`],
 ['negated-class',`const m=req.query.url.match(/([^x]+)/);if(m)launch(m[1]);`],
 ['negated-word',`const m=req.query.url.match(/(\\W+)/);if(m)launch('convert '+m[1]);`],
 ['escaped-pattern',`const re=/(.*)/;alter(re);const m=req.query.url.match(re);if(m)launch(m[1]);`],
 ['mutated-pattern',`const re=/(.*)/;re.exec=custom;const m=re.exec(req.query.url);if(m)launch(m[1]);`],
 ['stale-match',`let text=req.query.url;const re=/(.*)/;if(text.match(re)){text=clean(text);launch(text.match(re)[1]);}`],
])test('regex does not assert an unsupported or safe command: '+name,()=>assert.equal(count(run(body)),0));
test('restricted capture is not a safe attacker-selected executable',()=>assert.equal(count(run(`const m=req.query.url.match(/^([A-Za-z]+)$/);if(m)launch(m[1]);`)),1));
test('a character class is a choice, not a concatenated fixed string',()=>assert.equal(count(run(`const m=req.query.url.match(/^([ab])$/);if(m)launch(m[1]);`)),1));
test('regex planning never executes patterns and consumes existing budgets',()=>{
 const r=run(`const m=req.query.url.match(/((a+)+)$/);if(m)launch('convert '+m[1]);`);
 assert.equal(count(r),0);
 const low=analyze({files:[{filePath:'api.cjs',content:"const x=/(a)(b)(c)/;"}]},{maxSteps:1});
 assert.notEqual(low.status,'COMPLETE');
});
test('unrelated unknown external data write does not erase the request path',()=>{
 const r=analyze({files:[{filePath:'server.cjs',content:`const app=require('express')();const adapter=require('template-adapter');const extras=require('template-extras');adapter.views.helpers=extras;const launch=require('child_process').exec;app.post('/',(req,res)=>{const m=req.body.file.match(/(.*)/);if(m)launch('tool '+m[1]);});`}],nodeManifests:[{filePath:'package.json',express:'4.21.2'}]});
 assert.equal(count(r),1);assert.ok(r.files[0].limitations.includes('EXTERNAL_PROPERTY_WRITE_SCOPED_UNKNOWN'));
});
for(const change of ["adapter[unknownKey]=extras;","adapter.handler=launch;","adapter.handler=()=>launch('fixed');"])
test('related or dynamic external writes keep uncertainty: '+change,()=>{
 const r=analyze({files:[{filePath:'server.cjs',content:`const app=require('express')();const adapter=require('template-adapter');const extras=require('template-extras');const launch=require('child_process').exec;${change}app.post('/',(req,res)=>launch(req.body.file));`}],nodeManifests:[{filePath:'package.json',express:'4.21.2'}]});
 assert.equal(count(r),0);
});
