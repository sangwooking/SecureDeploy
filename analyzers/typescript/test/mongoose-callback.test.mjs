import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {callbackCases} from './mongoose-callback-cases.mjs';
const rule='JS_MONGOOSE_SELECTOR_INPUT_FLOW';
for(const c of callbackCases)test('Mongoose callback contract: '+c.id,()=>{
  const r=analyze(c.input),findings=r.findings.filter(f=>f.ruleId===rule),uses=r.nodeUses.filter(u=>u.ruleId===rule);
  assert.equal(findings.length,c.count,JSON.stringify({uses,files:r.files}));
  if(c.truth==='UNSUPPORTED')assert.ok(uses.some(u=>u.kind==='CALLBACK_VERSION_UNSUPPORTED'));
  if(c.truth==='UNKNOWN')assert.ok(uses.some(u=>u.kind==='UNKNOWN')||r.files.some(f=>f.limitations.some(l=>/MONGOOSE.*UNKNOWN/.test(l))));
  if(c.truth==='NORMAL')assert.ok(uses.some(u=>u.kind==='STATIC_OR_STRING_FILTER'));
  if(c.truth==='DEFENDED')assert.ok(uses.some(u=>u.kind==='SANITIZE_FILTER_DECLARED'));
  if(c.truth==='CREATED')assert.ok(uses.some(u=>u.kind==='QUERY_CREATED_EXECUTION_NOT_OBSERVED'));
  for(const f of findings){
    assert.equal(f.disposition,'REVIEW_REQUIRED');assert.ok(f.source.line>0&&f.sink.line>0);
    assert.ok(f.flow.some(l=>l.kind==='MONGOOSE_MODEL_DECLARATION'));
    assert.ok(f.flow.some(l=>['MONGOOSE_CALLBACK_EXECUTION_REQUEST','MONGOOSE_QUERY_EXECUTION_REQUEST'].includes(l.kind)));
    assert.ok(f.flow.every(l=>c.input.files.some(s=>s.filePath===l.filePath)));
  }
  if(c.id==='callback-body-not-run')assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW').length,0);
  if(c.id==='repeat-exec'||c.id==='callback-await'||c.id==='promise-repeat'){
    assert.ok(uses.some(u=>u.limitations.includes('MONGOOSE_REPEAT_OR_MIXED_EXECUTION_UNKNOWN')));
  }
  assert.deepEqual(analyze(c.input),r);
});
