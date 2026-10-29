import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {classCases} from './class-bootstrap-fixtures.mjs';
for(const c of classCases)test(`class bootstrap: ${c.id}`,()=>{
  const r=analyze({files:c.files}),warnings=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
  assert.equal(warnings.length,c.truth==='RISK'?1:0,JSON.stringify(r.files));
  if(c.truth==='RISK'){
    assert.equal(warnings[0].confidence,'HIGH');assert.equal(warnings[0].source.kind,'EXPRESS_BODY');
    assert.ok(r.nodeUses.some(u=>u.kind==='CLASS_CONSTRUCTED'));
    assert.ok(r.files.reduce((n,f)=>n+f.entrypoints,0)>0);
  }
  if(c.truth==='NORMAL')assert.ok(r.nodeUses.some(u=>u.kind==='STATIC_OR_DATA_ONLY'));
  if(c.truth==='UNKNOWN')assert.ok(r.files.some(f=>f.limitations.length>0));
  assert.equal(r.files.some(f=>f.parseStatus==='PARSE_FAILED'),false);
  assert.deepEqual(analyze({files:c.files}),r);
});
test('class traversal uses existing depth and result budgets',()=>{
  const c=classCases.find(c=>c.id==='constructor-nested-method');
  const r=analyze({files:c.files},{maxDepth:1});
  assert.ok(r.files.some(f=>f.limitations.some(l=>l.includes('DEPTH'))));
  assert.equal(r.findings.length,0);
});
test('constructor function fields stay explicitly unsupported rather than losing this silently',()=>{
  const r=analyze({files:[{filePath:'server.js',content:`const app=require('express')();
    class Helper{constructor(){this.value='1';this.run=()=>eval(this.value);}}
    const h=new Helper();app.post('/a',(req,res)=>{if(req.query.enabled){h.value=req.body.code;h.run();}});
    app.post('/b',(req,res)=>h.run());`}]});
  assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW').length,0);
  assert.ok(r.files.some(f=>f.limitations.includes('CLASS_CONSTRUCTOR_CONTROL_FLOW_UNKNOWN')));
});
