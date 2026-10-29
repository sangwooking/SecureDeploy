import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateClasses,summarize} from './class35.mjs';
import {readFileSync} from 'node:fs';
test('class evidence controls separate detection, no-entry and unsupported outcomes',()=>{
  const rows=evaluateClasses(),s=summarize(rows);
  assert.equal(s.risk,11);assert.equal(s.supportedRiskDetected,11);assert.equal(s.normal,3);
  assert.equal(s.noEntry,5);assert.equal(s.unknown,16);assert.equal(s.normalWarnings,0);
  assert.equal(s.realAppTP,0);assert.equal(s.independent,false);
  for(const c of rows)assert.match(c.sourceSha256,/^[a-f0-9]{64}$/);
});
test('closeout receipt keeps unavailable inputs separate from executed regressions',()=>{
  const text=readFileSync(new URL('./class35-closeout-summary.json',import.meta.url),'utf8');
  const r=JSON.parse(text),missing=r.inputs.filter(p=>p.status==='NOT_RUN'),executed=r.inputs.filter(p=>p.status==='REPEATED_WITH_SCOPE_LIMITS');
  assert.equal(r.worker,'ts-server-v47');assert.equal(r.inputs.length,15);
  assert.equal(missing.length,7);assert.equal(executed.length,8);
  assert.ok(missing.every(p=>p.reason==='INPUT_UNAVAILABLE'&&!p.repeats));
  assert.ok(executed.every(p=>p.repeats===2&&p.repeatIdentical&&p.currentEntries===p.historicalEntries));
  assert.equal(new Set(executed.map(p=>p.projectId)).size,7);
  assert.ok(r.inputs.every(p=>/^[a-f0-9]{40}$/.test(p.sourceSha)));
  assert.equal(r.allFifteenInputsReplayed,false);assert.equal(r.newRealVulnerabilityTP,0);
  assert.equal(r.flint.vulnerableFixedDistinctionVerified,false);assert.equal(r.flint.beforeAndAfterRequestEntries,0);
  assert.equal(r.actualTargetContrast.nodeGoatExistingRiskSinkPaths,4);
  assert.equal(r.preservation.userDatabaseChanged,false);assert.equal(r.preservation.userServerRestarted,false);
  const observed=summarize(evaluateClasses());
  assert.equal(observed.supportedRiskDetected,r.classControls.v47Detected);
  assert.equal(observed.unknown,r.classControls.unknown);
  assert.ok(!text.includes('/Users/'));assert.ok(!text.includes('/private/tmp/'));
});
