import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {analyze,VERSION} from '../../analyzers/typescript/analyzer.mjs';
import {middlewareCases,input} from '../../analyzers/typescript/test/middleware-control-fixtures.mjs';

const text=fs.readFileSync(new URL('./middleware35-summary.json',import.meta.url),'utf8');
const summary=JSON.parse(text);
test('fixed control source hashes, retained candidates and positive exit evidence match the current worker',()=>{
  assert.equal(summary.currentWorker,'ts-server-v46');assert.ok(['ts-server-v46','ts-server-v47','ts-server-v48','ts-server-v49'].includes(VERSION));
  assert.equal(summary.controls.length,middlewareCases.length);
  for(const [i,c]of middlewareCases.entries()){
    const row=summary.controls[i];assert.equal(row.id,c.id);assert.equal(row.contractExpectation,c.truth);
    assert.equal(row.sourceSha256,createHash('sha256').update(c.code).digest('hex'));
    const r=analyze(input(c));
    assert.equal(r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW').length,row.afterWarnings,c.id);
    if(c.truth==='BLOCKED')assert.ok(r.nodeUses.some(u=>u.kind==='ROUTE_HANDLER_NOT_REACHED'),c.id);
    if(c.truth==='UNKNOWN_RETAIN')assert.equal(row.beforeWarnings,row.afterWarnings,c.id);
  }
});
test('published scope does not turn control improvements into independent TP, global safety or automatic patch readiness',()=>{
  assert.equal(summary.findingRuleIds,72);assert.equal(summary.newRules,0);
  assert.equal(summary.newRealVulnerabilityTP,0);assert.equal(summary.remediationReady,0);
  assert.equal(summary.actualTargetCases.filter(c=>c.before==='TP').length,4);
  assert.equal(summary.actualTargetCases.filter(c=>c.before==='NOT_SUPPORTED_REQUEST_CONNECTION').length,3);
  assert.equal(summary.counts.BLOCKED.afterWarnings,0);
  assert.equal(summary.counts.REACHABLE.afterWarnings,11);
  assert.equal(summary.counts.UNKNOWN_RETAIN.afterWarnings,17);
  assert.equal(summary.existingApplications.length,15);
  assert.ok(summary.existingApplications.every(p=>p.repeatIdentical&&p.targetFindingsPreservedExceptVersionScopedIdentity));
  assert.equal(summary.userServerRestarted,false);assert.equal(summary.userDatabaseChanged,false);
  assert.ok(!text.includes('/Users/'));assert.ok(!text.includes('/private/tmp/'));
});
