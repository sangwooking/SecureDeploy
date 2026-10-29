import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateConstructors} from './constructor35.mjs';
test('constructor controls keep positive, conditional, blocked and unsupported paths separate',()=>{
 const rows=evaluateConstructors();assert.equal(rows.length,31);
 for(const r of rows){
  assert.match(r.sourceSha256,/^[a-f0-9]{64}$/);
  assert.equal(r.high,r.expectation==='HIGH'?1:0,r.id);
  assert.equal(r.medium,r.expectation==='TWO_CONDITIONAL'?2:r.expectation==='CONDITIONAL'?1:0,r.id);
  if(r.expectation==='NORMAL')assert.ok(r.entries>0,r.id);
 }
});
