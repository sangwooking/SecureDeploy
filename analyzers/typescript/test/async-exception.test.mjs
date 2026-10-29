import{test}from'node:test';import assert from'node:assert/strict';
import{analyze}from'../analyzer.mjs';import{asyncExceptionCases}from'./async-exception-fixtures.mjs';
for(const c of asyncExceptionCases)test(`bounded async exception: ${c.id}`,()=>{
 const r=analyze({files:c.files}),f=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
 assert.equal(f.length,c.expected==='CONDITIONAL'?1:0,c.id+':'+JSON.stringify(r.files));
 if(f.length)assert.equal(f[0].confidence,'MEDIUM');
 if(c.expected==='UNKNOWN')assert.ok(r.files.some(f=>f.limitations.length));
 assert.deepEqual(analyze({files:c.files}),r);
});
const run=body=>analyze({files:[{filePath:'entry.cjs',content:`const app=require('express')();app.post('/',async(req,res)=>{${body}});`}]});
test('unknown catch calls stop before later sinks and do not prove handled completion',()=>{
 const r=run(`try{await Promise.reject('x');}catch(e){external();eval(req.body.code);}eval(req.body.other);`);
 assert.equal(r.findings.length,0);assert.ok(r.files[0].limitations.includes('ASYNC_EXCEPTION_CALL_COMPLETION_UNKNOWN'));
});
test('property reads, writes and temporal dead zone are not accepted as exception-free handling',()=>{
 for(const body of [`try{throw 'x';}catch(e){const v=e.value;}eval(req.body.code);`,`try{throw 'x';}catch(e){holder.value=1;}eval(req.body.code);`,`try{unknownName;}catch(e){return;}eval(req.body.code);`,`try{const a=b;const b=1;}catch(e){return;}eval(req.body.code);`])assert.equal(run(body).findings.length,0);
});
test('catch is not entered on modeled fulfillment and finally return overrides try return',()=>{
 const r=run(`try{await Promise.resolve(0);}catch(e){eval(req.body.other);}eval(req.body.code);`);
 assert.equal(r.findings.length,1);assert.ok(!r.nodeUses.some(u=>u.kind==='ASYNC_CATCH_ENTERED'));
 const safe=analyze({files:[{filePath:'entry.cjs',content:`const app=require('express')();async function value(v){try{return v;}finally{return '1';}}
 app.post('/',async(req,res)=>{const v=await value(req.body.code);eval(v);eval(req.body.other);});`}]});
 assert.equal(safe.findings.length,1);assert.equal(safe.findings[0].source.kind,'EXPRESS_BODY');
 assert.ok(safe.nodeUses.some(u=>u.kind==='ASYNC_FINALLY_ENTERED'));
 const thrown=analyze({files:[{filePath:'entry.cjs',content:`const app=require('express')();async function value(){try{return '1';}finally{throw 'x';}}
 app.post('/',async(req,res)=>{await value();eval(req.body.code);});`}]});
 assert.equal(thrown.findings.length,0);assert.ok(thrown.nodeUses.some(u=>u.kind==='ASYNC_EXCEPTION_PROPAGATED'));
});
test('handled primitive returns remain symbolic promises rather than immediate tainted values',()=>{
 const input={files:[{filePath:'entry.js',content:`const app=require('express')();async function value(){try{await Promise.reject('x');}catch(e){return '1';}}
 app.post('/',async(req,res)=>{const v=await value();eval(v);eval(req.body.code);});`}]};
 const r=analyze(input);assert.equal(r.findings.length,1);assert.equal(r.findings[0].confidence,'MEDIUM');
});
test('catch cannot see a block-local try declaration and outer bindings are restored',()=>{
 const r=run(`const x=req.body.code;try{const x='1';await Promise.reject('x');}catch(e){eval(x);}`);
 assert.equal(r.findings.length,1);assert.equal(r.findings[0].confidence,'MEDIUM');
 assert.ok(r.nodeUses.some(u=>u.kind==='ASYNC_CATCH_ENTERED'));
});
test('post-suspension this state and separate invocations are not merged into a safe proof',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();class S{constructor(v){this.value=v;}async run(){try{await Promise.reject('x');}catch(e){eval(this.value);}}}
 app.post('/',(req,res)=>{new S(req.body.code).run();new S('1').run();});`}]});
 assert.equal(r.findings.length,0);
 assert.ok(r.nodeUses.some(u=>u.kind==='ASYNC_CATCH_ENTERED'));
});
test('bounded exception paths preserve depth and step exhaustion as incomplete',()=>{
 const r=analyze({files:asyncExceptionCases[0].files},{maxSteps:45});assert.equal(r.findings.length,0);assert.ok(r.files.some(f=>f.limitations.length));
});
test('a confirmed synchronous throw can register an existing handler but an unknown await cannot',()=>{
 const source=operation=>`const app=require('express')();const handler=(req,res)=>eval(req.body.code);async function boot(){try{${operation}}catch(e){app.post('/',handler);}}boot();`;
 const known=analyze({files:[{filePath:'entry.js',content:source(`throw 'x';`)}]});
 assert.equal(known.findings.length,1);assert.equal(known.findings[0].confidence,'MEDIUM');
 const opaque=analyze({files:[{filePath:'entry.js',content:source(`await external();`)}]});assert.equal(opaque.findings.length,0);
});
test('unverified Error shadow and inline callbacks are not silently executed as native handling',()=>{
 for(const setup of [`const Error=external;`,`Error=external;`,`external(Error);`]){
  const r=run(`${setup}try{throw 'x';}catch(e){throw Error('x');}eval(req.body.code);`);
  assert.equal(r.findings.length,0);assert.ok(r.files[0].limitations.includes('ASYNC_EXCEPTION_EXPRESSION_COMPLETION_UNKNOWN'));
 }
 const inline=run(`try{throw 'x';}catch(e){external(()=>eval(req.body.code));}`);assert.equal(inline.findings.length,0);
});
test('conditional exception paths do not promote other sinks or contaminate an independent request',()=>{
 const r=analyze({files:[{filePath:'entry.js',content:`const app=require('express')();const fs=require('fs');
 app.post('/',async(req,res)=>{try{await Promise.reject('x');}catch(e){}fetch(req.body.url);fs.readFileSync(req.body.path);res.json({value:process.env.API_SECRET});});
 app.get('/other',(req,res)=>eval(req.query.code));`}]});
 assert.ok(r.findings.some(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='MEDIUM'));
 assert.equal(r.findings.filter(f=>f.confidence==='HIGH').length,1);
 assert.equal(r.findings.find(f=>f.confidence==='HIGH').ruleId,'JS_EVAL_INPUT_FLOW');
 assert.ok(r.resourceUses.some(u=>u.kind==='UNRESOLVED_RESOURCE'));
});
test('a throw after I/O fulfillment is separate from that await rejection and is not double-counted',()=>{
 const r=run(`const {writeFile}=require('fs/promises');try{await writeFile('unused.txt','data');throw 'after';}catch(e){return;}eval(req.body.code);`);
 assert.equal(r.findings.length,0);
 assert.ok(r.nodeUses.some(u=>u.kind==='ASYNC_REJECTION_CAPTURED'));
 assert.ok(r.nodeUses.some(u=>u.kind==='ASYNC_THROW_CAPTURED'));
 const rejected=run(`try{await Promise.reject('x');}catch(e){return;}`);
 assert.ok(!rejected.nodeUses.some(u=>u.kind==='ASYNC_THROW_CAPTURED'));
});
