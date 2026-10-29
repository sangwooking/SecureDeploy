import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateFileIo} from './fileio35.mjs';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
test('fixed file IO controls separate conditional completion from unknown and blocked flows',()=>{
 const rows=evaluateFileIo();assert.equal(rows.length,23);
 for(const r of rows){const current=['catch-not-modeled','rethrow-not-modeled','finally-not-modeled'].includes(r.id)?'CONDITIONAL':r.expected;
  assert.equal(r.high,current==='HIGH'?1:0,r.id);assert.equal(r.medium,current==='CONDITIONAL'?1:0,r.id);}
 assert.equal(rows.filter(r=>r.expected==='UNKNOWN').length,11);
});
test('file IO receipt distinguishes source continuity from real vulnerability detection',()=>{
 const text=readFileSync(new URL('./fileio35-summary.json',import.meta.url),'utf8'),r=JSON.parse(text),rows=evaluateFileIo();
 assert.equal(r.worker,'ts-server-v50');assert.equal(r.newRealVulnerabilityTP,0);
 assert.equal(r.flint.databaseLine108Reached,false);assert.equal(r.flint.nextBoundary.line,107);
 assert.equal(r.flint.callerAwait.conditionalContinuationObserved,true);
 assert.equal(r.regression.evaluatedInputs,8);assert.equal(r.regression.unavailableInputs,7);
 assert.equal(r.regression.allFifteenPassed,false);assert.equal(r.apiContracts.runtimeNodeVersionAndSpecifierAvailabilityVerified,false);
 assert.equal(createHash('sha256').update(JSON.stringify(rows.map(x=>({id:x.id,expected:x.expected,sourceSha256:x.sourceSha256})))).digest('hex'),r.controls.catalogSha256);
 assert.equal(rows.filter(x=>!['catch-not-modeled','rethrow-not-modeled','finally-not-modeled'].includes(x.id)).reduce((n,x)=>n+x.medium,0),r.controls.conditionalTargets.v50Medium);
 assert.ok(!text.includes('/Users/'));assert.ok(!text.includes('/private/tmp/'));
});
