import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateClasses,summarize} from './class35.mjs';
test('class evidence controls separate detection, no-entry and unsupported outcomes',()=>{
  const rows=evaluateClasses(),s=summarize(rows);
  assert.equal(s.risk,11);assert.equal(s.supportedRiskDetected,11);assert.equal(s.normal,3);
  assert.equal(s.noEntry,5);assert.equal(s.unknown,16);assert.equal(s.normalWarnings,0);
  assert.equal(s.realAppTP,0);assert.equal(s.independent,false);
  for(const c of rows)assert.match(c.sourceSha256,/^[a-f0-9]{64}$/);
});
