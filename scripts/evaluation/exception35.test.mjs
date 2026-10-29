import{test}from'node:test';import assert from'node:assert/strict';import{evaluateExceptions}from'./exception35.mjs';
import{auditRouteDiscovery}from'./routefirst35.mjs';
import{readFileSync}from'node:fs';import{createHash}from'node:crypto';
test('bounded exceptions preserve fixed conditional, terminated and unknown controls',()=>{
 const rows=evaluateExceptions();assert.equal(rows.length,20);for(const r of rows){assert.equal(r.high,0,r.id);assert.equal(r.medium,r.expected==='CONDITIONAL'?1:0,r.id);}
});
test('exception receipt separates operand inspection, helper invocation and runtime route exposure',()=>{
 const text=readFileSync(new URL('./exception35-summary.json',import.meta.url),'utf8'),r=JSON.parse(text),rows=evaluateExceptions();
 assert.equal(r.worker,'ts-server-v51');assert.equal(r.newRealVulnerabilityTP,0);
 assert.equal(r.flint.tryLine107Entered,true);assert.equal(r.flint.awaitOperandLine108Evaluated,true);
 assert.equal(r.flint.helperBodyReached,false);assert.equal(r.flint.databaseConnectionInvoked,false);assert.equal(r.flint.httpEntries,0);
 assert.equal(r.routeFirstAudit.productImplementationAdded,false);assert.equal(r.routeFirstAudit.allRoutesRequireCompleteBootstrap,false);
 assert.equal(r.regression.unavailableInputs,7);assert.equal(r.regression.allFifteenPassed,false);
 assert.equal(createHash('sha256').update(JSON.stringify(rows.map(x=>({id:x.id,expected:x.expected,sourceSha256:x.sourceSha256})))).digest('hex'),r.controls.catalogSha256);
 assert.equal(rows.reduce((n,x)=>n+x.medium,0),r.controls.conditionalTargets.v51Medium);
 assert.ok(!text.includes('/Users/'));assert.ok(!text.includes('/private/tmp/'));
});
test('existing discovery is not full bootstrap proof or arbitrary factory invocation',()=>{
 const r=auditRouteDiscovery();assert.deepEqual(r.map(x=>x.entries),[1,0,0,1,0]);
 assert.ok(r[0].registration.every(u=>u.limitations.includes('STATIC_REGISTRATION_ONLY')));
 assert.ok(r[2].limitations.includes('UNMOUNTED_ROUTER_NOT_ANALYZED'));
});
