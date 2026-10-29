import{test}from'node:test';import assert from'node:assert/strict';import{evaluateStaticRouteControls}from'./static-route35.mjs';
import{auditHelperReferences}from'./reference35.mjs';
import{readFileSync}from'node:fs';
test('fixed candidate cases keep product observations separate from diagnostic flows',()=>{
 const rows=evaluateStaticRouteControls();assert.equal(rows.length,21);
 for(const r of rows){assert.equal(r.riskApplied,false);assert.equal(r.ruleObservations.length,r.expectedRuleObservations,r.id);}
 assert.equal(rows.find(x=>x.id==='unmounted-input').productionFindings,0);
 assert.equal(rows.find(x=>x.id==='mounted-app').productionFindings,1);
});
test('reference audit isolates module success, branch merge and post-await heap uncertainty',()=>{
 const r=auditHelperReferences();assert.equal(r[0].findings.length,1);assert.ok(r.slice(1).every(x=>x.findings.length===0));
 assert.ok(r[1].states.some(u=>u.kind==='ASYNC_HELPER_REFERENCE_UNVERIFIED'));
 assert.ok(r[2].limitations.some(f=>f.limitations.includes('POST_AWAIT_HEAP_STATE_UNKNOWN')));
 assert.ok(r.every(x=>x.limitations.every(f=>!f.limitations.includes('NODE_MODULE_RESOLUTION_UNKNOWN'))));
});
test('closeout metadata separates conditional observations, product regression and missing inputs',()=>{
 const s=JSON.parse(readFileSync(new URL('./static-route35-summary.json',import.meta.url),'utf8'));
 assert.equal(s.worker,'ts-server-v51');assert.equal(s.evaluationOnly,true);assert.equal(s.newRealTP,0);
 assert.equal(s.productionRegression.availableHistoricalInputs,8);assert.equal(s.productionRegression.missingHistoricalInputs.length,7);
 assert.ok(s.productionRegression.missingHistoricalInputs.every(i=>i.status==='NOT_RUN'&&i.reason==='INPUT_UNAVAILABLE'));
 assert.equal(s.productionRegression.all14EqualExceptCodeFingerprint,true);assert.equal(s.productionRegression.nodeGoatSinkPathsPreserved,4);
 assert.equal(s.prototypeInputs.length,14);assert.ok(s.prototypeInputs.every(i=>i.repeatIdentical&&i.ruleObservations===0&&i.steps<=100000));
 const flint=s.prototypeInputs.filter(i=>i.projectId==='JasonEtco--flintcms');assert.equal(flint.length,2);
 for(const f of flint){assert.deepEqual(f.categories,{B:3,C:12,D:1,E:2});assert.equal(f.traceStates.ANALYZED_CONDITIONAL,10);}
 assert.equal(s.flint.mongooseReceiver,'UNVERIFIED');assert.equal(s.helperAudit.referenceRestorationImplemented,false);
 assert.equal(s.integration.prototypeLeak,false);assert.equal(s.preservation.userServerRestarted,false);
 assert.ok(Object.values(s.preservation).every(v=>v===false));assert.equal(s.validation.testFailures,0);
});
