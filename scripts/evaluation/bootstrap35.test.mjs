import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {controls,evaluateControls} from './bootstrap35.mjs';

test('bootstrap controls preserve explicit connections and deferred activation boundaries',()=>{
  const rows=evaluateControls();
  assert.equal(rows.length,controls.length);
  for(const row of rows){
    assert.equal(row.observedCount,row.expectedCount,row.id);
    if(row.expected==='FLOW')assert.equal(row.highCount,row.expectedCount,row.id);
    if(row.expected==='SAFE_TARGET')assert.ok(row.entries>0,row.id);
    if(row.expected==='DEFERRED')assert.ok(row.limitations.length>0,row.id);
  }
});

test('published outcome never turns adapter progress or blocked middleware into real TP',()=>{
  const load=name=>JSON.parse(fs.readFileSync(new URL(name,import.meta.url),'utf8'));
  const catalog=load('./bootstrap35-catalog.json'),summary=load('./bootstrap35-summary.json');
  assert.equal(summary.endToEndGoalMet,false);
  assert.equal(summary.newRealVulnerabilityTP,0);
  assert.equal(summary.ruleCount,72);
  assert.equal(summary.actualCases.filter(c=>c.before==='TP').length,4);
  assert.equal(summary.actualCases.filter(c=>c.before==='NOT_SUPPORTED_REQUEST_CONNECTION').length,3);
  assert.equal(summary.controls.length,controls.length);
  assert.equal(summary.knownBlockedMiddleware.afterWarnings,1);
  assert.equal(catalog.commonality.sameFirstFailure,false);
  assert.equal(catalog.productEngineChanged,true);
  assert.ok(summary.existingApplications.every(p=>p.changedSemanticFields.length===0&&p.versionScopedIdsVerified));
  assert.ok(!JSON.stringify(summary).includes('/Users/'));
  assert.ok(!JSON.stringify(summary).includes('/private/tmp/'));
});
