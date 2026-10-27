import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {injection24Cases} from './injection24-cases.mjs';
export function target(r,c){return r.findings.filter(f=>f.ruleId===(c.track==='SQL'?'JS_SEQUELIZE_SQL_INPUT_FLOW':'JS_MONGOOSE_SELECTOR_INPUT_FLOW')&&f.confidence==='HIGH');}
for(const c of injection24Cases)test('injection precision: '+c.id,()=>{
 const r=analyze(c.input),hits=target(r,c);
 assert.equal(hits.length,c.truth==='RISK'?1:0,JSON.stringify(r.nodeUses));
 if(hits.length){assert.equal(hits[0].disposition,'REVIEW_REQUIRED');assert.ok(hits[0].source);assert.ok(hits[0].sink);}
 if(c.truth==='NORMAL')assert.ok(r.nodeUses.some(u=>['STATIC_OR_DATA_ONLY','STATIC_OR_STRING_FILTER','SANITIZE_FILTER_DECLARED'].includes(u.kind)),JSON.stringify(r.nodeUses));
 if(c.truth==='UNKNOWN'){
  const rule=c.track==='SQL'?'JS_SEQUELIZE_SQL_INPUT_FLOW':'JS_MONGOOSE_SELECTOR_INPUT_FLOW';
  assert.ok(!r.nodeUses.some(u=>u.ruleId===rule&&['STATIC_OR_DATA_ONLY','STATIC_OR_STRING_FILTER','SANITIZE_FILTER_DECLARED'].includes(u.kind)));
 }
});
test('shared filter fanout is bounded and unresolved, not a safe or confirmed query',()=>{
 const c=structuredClone(injection24Cases.find(c=>c.id==='mongo-shared-body'));
 const fields=value=>Array.from({length:32},(_,i)=>`f${i}:${value}`).join(',');
 c.input.files[0].content=c.input.files[0].content.replace('const x=req.body;await Model.findOne({email:x,password:x});',
  `const leaf={value:req.body.email};const row={${fields('leaf')}};const filter={${fields('row')}};await Model.findOne(filter);`);
 const r=analyze(c.input);assert.equal(target(r,c).length,0);
 assert.ok(r.files.some(f=>f.limitations.includes('MONGOOSE_FILTER_SCAN_LIMIT')));
 assert.ok(r.nodeUses.some(u=>u.kind==='UNKNOWN'));
 assert.ok(r.supabaseAnalysis.budgetUsage.STEPS_USED<=100000);
});
