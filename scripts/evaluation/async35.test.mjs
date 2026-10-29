import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateAsync} from './async35.mjs';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
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
test('async receipt keeps completion uncertainty and real detection results separate',()=>{
 const text=readFileSync(new URL('./async35-summary.json',import.meta.url),'utf8');const r=JSON.parse(text);
 assert.equal(r.worker,'ts-server-v49');assert.equal(r.newRealVulnerabilityTP,0);
 assert.equal(r.flint.databaseCall.workerReached,false);assert.equal(r.flint.targetSourceSinkConnected,false);
 assert.equal(r.flint.firstAwait.line,96);assert.equal(r.flint.nestedAwait.line,56);
 assert.equal(r.actualTargets.nodeGoatExistingRiskSinkPaths,4);
 assert.equal(r.regression.unavailableInputs,7);assert.equal(r.regression.allFifteenPassed,false);
 assert.equal(r.databaseContextStaticReviewOnly.runtimeConnectionOrEventConfirmed,false);
 const rows=evaluateAsync();
 assert.equal(createHash('sha256').update(JSON.stringify(rows.map(x=>({id:x.id,expected:x.expected,sourceSha256:x.sourceSha256})))).digest('hex'),r.controls.catalogSha256);
 assert.equal(rows.reduce((n,x)=>n+x.high,0),r.controls.preAwaitRiskCases.v49High);
 assert.equal(rows.reduce((n,x)=>n+x.medium,0),r.controls.conditionalCases.v49Medium);
 assert.ok(!text.includes('/Users/'));assert.ok(!text.includes('/private/tmp/'));
});
