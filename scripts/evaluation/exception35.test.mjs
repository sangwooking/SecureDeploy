import{test}from'node:test';import assert from'node:assert/strict';import{evaluateExceptions}from'./exception35.mjs';
import{auditRouteDiscovery}from'./routefirst35.mjs';
test('bounded exceptions preserve fixed conditional, terminated and unknown controls',()=>{
 const rows=evaluateExceptions();assert.equal(rows.length,20);for(const r of rows){assert.equal(r.high,0,r.id);assert.equal(r.medium,r.expected==='CONDITIONAL'?1:0,r.id);}
});
test('existing discovery is not full bootstrap proof or arbitrary factory invocation',()=>{
 const r=auditRouteDiscovery();assert.deepEqual(r.map(x=>x.entries),[1,0,0,1,0]);
 assert.ok(r[0].registration.every(u=>u.limitations.includes('STATIC_REGISTRATION_ONLY')));
 assert.ok(r[2].limitations.includes('UNMOUNTED_ROUTER_NOT_ANALYZED'));
});
