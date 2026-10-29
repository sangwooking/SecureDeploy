import{test}from'node:test';import assert from'node:assert/strict';import{evaluateStaticRouteControls}from'./static-route35.mjs';
import{auditHelperReferences}from'./reference35.mjs';
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
