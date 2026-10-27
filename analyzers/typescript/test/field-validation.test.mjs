import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {fieldCases,fieldInput} from './field-cases.mjs';
const rule='JS_MONGOOSE_SELECTOR_INPUT_FLOW';
for(const c of fieldCases)test('field scoped validation: '+c.id,()=>{
  const r=analyze(c.input),fs=r.findings.filter(f=>f.ruleId===rule),uses=r.nodeUses.filter(u=>u.ruleId===rule);
  assert.equal(fs.length,c.truth==='RISK'&&!c.knownGap?1:0,JSON.stringify({uses,files:r.files}));
  if(c.knownGap)assert.ok(uses.some(u=>u.kind===c.expectedState),c.knownGap);
  if(c.truth==='NORMAL')assert.ok(uses.some(u=>u.kind==='STATIC_OR_STRING_FILTER'));
  if(c.truth==='UNKNOWN')assert.ok(uses.some(u=>u.kind==='UNKNOWN')||r.files.some(f=>f.limitations.some(l=>/UNKNOWN|UNRESOLVED/.test(l))));
  if(c.truth==='CREATED')assert.ok(uses.some(u=>u.kind==='QUERY_CREATED_EXECUTION_NOT_OBSERVED'));
  for(const f of fs){
    const source=c.input.files.find(x=>x.filePath===f.source.filePath).content.split('\n')[f.source.line-1].slice(f.source.column-1);
    assert.ok(source.startsWith(c.source),JSON.stringify({expected:c.source,source,f}));
    assert.equal(f.disposition,'REVIEW_REQUIRED');assert.ok(!f.recommendation.includes('자동 수정 완료'));
  }
  if(c.id==='format-one-field')assert.ok(fs[0].defenses.some(d=>d.kind==='FIELD_EMAIL_ACCEPTED_BRANCH'));
  if(c.id==='reverse-branch')assert.ok(fs[0].defenses.some(d=>d.kind==='FIELD_EMAIL_REJECTED_BRANCH'));
  assert.deepEqual(analyze(c.input),r);
  assert.ok(!JSON.stringify(r).includes('fieldOrigin'));
});
test('string type proof is not SQL/code sanitization',()=>{
  const r=analyze(fieldInput("if(typeof req.body.program!=='string')return;eval(req.body.program);"));
  assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW').length,1);
});
test('field facts cannot contaminate another request',()=>{
  const input=fieldInput("if(typeof req.body.credential!=='string')return;Model.findOne({pass:req.body.credential},()=>{});");
  input.files[0].content+="app.post('/other',async(req,res)=>{Model.findOne({pass:req.body.credential},()=>{});});";
  const r=analyze(input);assert.equal(r.findings.filter(f=>f.ruleId===rule).length,1);
});
