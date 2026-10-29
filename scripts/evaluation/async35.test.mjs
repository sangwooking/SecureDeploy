import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateAsync} from './async35.mjs';
test('async control results separate pre-await execution, conditional resume and unsupported completion',()=>{
 const rows=evaluateAsync();assert.equal(rows.length,24);
 for(const r of rows){
  assert.equal(r.high,r.expected==='HIGH'?1:0,r.id);assert.equal(r.medium,r.expected==='CONDITIONAL'?1:0,r.id);
  assert.match(r.sourceSha256,/^[a-f0-9]{64}$/);
  if(r.expected==='UNKNOWN')assert.ok(r.limitations.length>0);
 }
 assert.ok(rows.find(r=>r.id==='promise-not-value').states.includes('ASYNC_CALL_CONNECTED'));
 assert.ok(rows.find(r=>r.id==='native-reject').states.includes('REJECTION_PATH_POSSIBLE'));
});
