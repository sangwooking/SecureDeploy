import {test} from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {evaluate} from './context25.mjs';
test('same-author receipt distinguishes warnings, unsupported risk misses and normal deferral',async()=>{
 const r=await evaluate(fileURLToPath(new URL('../../',import.meta.url)));
 assert.equal(r.rows.length,43);
 assert.equal(r.xss.TP,5);assert.equal(r.xss.FP,1);assert.equal(r.xss.TN,9);
 // #30 keeps the original case truth and receipt, but repairs HTTP branch/href flow.
 assert.equal(r.ssrf.TP,9);assert.equal(r.ssrf.FN,3);assert.equal(r.ssrf.TN,6);
 assert.equal(r.ssrf.NORMAL_DEFERRED,0);
 for(const counts of [r.xss,r.ssrf]){
  assert.equal(counts.UNEXPECTED_CANDIDATE,0);assert.equal(counts.FALSE_SAFE_OBSERVATION,0);
 }
 assert.equal(r.rows.find(c=>c.id==='xss-purified').outcome,'FP');
 assert.equal(r.rows.find(c=>c.id==='ssrf-allowed').outcome,'TN');
 assert.ok(r.sqlConditional.some(u=>u.kind==='STATIC_OR_DATA_ONLY'));
});
