import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateConstructors} from './constructor35.mjs';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
test('constructor controls keep positive, conditional, blocked and unsupported paths separate',()=>{
 const rows=evaluateConstructors();assert.equal(rows.length,31);
 for(const r of rows){
  assert.match(r.sourceSha256,/^[a-f0-9]{64}$/);
  assert.equal(r.high,r.expectation==='HIGH'?1:0,r.id);
  assert.equal(r.medium,r.expectation==='TWO_CONDITIONAL'?2:r.expectation==='CONDITIONAL'?1:0,r.id);
  if(r.expectation==='NORMAL')assert.ok(r.entries>0,r.id);
 }
});
test('published constructor receipt distinguishes symbolic reachability from real vulnerability success',()=>{
 const text=readFileSync(new URL('./constructor35-summary.json',import.meta.url),'utf8');const r=JSON.parse(text);
 assert.equal(r.worker,'ts-server-v48');assert.equal(r.newRealVulnerabilityTP,0);
 assert.equal(r.regression.evaluatedInputs,8);assert.equal(r.regression.unavailableInputs,7);assert.equal(r.regression.allFifteenPassed,false);
 assert.equal(r.actualTargets.nodeGoatRiskSinkPaths,4);assert.equal(r.flint.targetSourceSinkConnected,false);
 assert.equal(r.flint.newBoundary.targetLine,94);assert.equal(r.flint.databaseOpenEventReached,false);
 assert.ok(r.regression.inputs.every(p=>p.currentSteps===p.baselineSteps));
 const rows=evaluateConstructors();
 const digest=createHash('sha256').update(JSON.stringify(rows.map(x=>({id:x.id,expectation:x.expectation,sourceSha256:x.sourceSha256})))).digest('hex');
 assert.equal(digest,r.controls.catalogSha256);
 assert.equal(rows.reduce((n,x)=>n+x.high,0),r.controls.knownReachableCases.v48High);
 assert.equal(rows.reduce((n,x)=>n+x.medium,0),r.controls.conditionalCases.v48Medium);
 assert.ok(!text.includes('/Users/'));assert.ok(!text.includes('/private/tmp/'));
});
