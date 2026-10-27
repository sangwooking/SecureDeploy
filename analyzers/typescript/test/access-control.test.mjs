import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {accessCases,accessInput} from './access-control-cases.mjs';
for(const c of accessCases)test('access-control evidence: '+c.id,()=>{
 const r=analyze(c.input),access=r.supabaseAnalysis.accesses[0],e=access.authorizationEvidence;
 const filters=e.authChecks.flatMap(c=>c.resultEvidence?.userIdFilters??[]);
 assert.equal(filters.length,c.observedExpected??c.expected,c.id);
 assert.equal(e.effectiveRole,'UNKNOWN');
 assert.ok(e.limitations.includes('APPLICATION_FILTER_NOT_DATABASE_AUTHORIZATION'));
 assert.ok(!r.findings.some(f=>/IDOR|BOLA|MISSING_AUTH|ADMIN_MISSING/.test(f.ruleId)));
 assert.ok(!JSON.stringify(e).includes('AUTHENTICATED_SUCCESS'));
 if(filters.length){
  assert.ok(e.requestEntry);assert.equal(access.clientStatus,'CLIENT_DECLARATION_LINKED');
  for(const l of filters){assert.equal(l.kind,'IDENTITY_RESULT_ID_FILTER_OBSERVED');assert.ok(l.line>0&&l.column>0);}
 }
 assert.deepEqual(analyze(c.input),r);
});
test('arbitrary columns do not acquire ownership meaning and missing SQL remains unknown',()=>{
 const input=accessInput("const {data:{user}}=await db.auth.getUser();if(!user)return;const identity=user.id;return db.from('records').delete().match({unrelated:identity});");
 input.policyFiles=[];
 const a=analyze(input).supabaseAnalysis.accesses[0];
 assert.equal(a.authorizationEvidence.authChecks[0].resultEvidence.userIdFilters.length,1);
 assert.equal(a.authorizationEvidence.state,'UNKNOWN');assert.equal(a.authorizationEvidence.effectiveRole,'UNKNOWN');
});
test('oversized match objects and low budgets do not fabricate filter proof',()=>{
 const body="const {data:{user}}=await db.auth.getUser();if(!user)return;return db.from('records').select().match({"+Array.from({length:17},(_,i)=>`f${i}:user.id`).join(',')+"});";
 const input=accessInput(body),r=analyze(input);
 assert.equal(r.supabaseAnalysis.accesses[0].authorizationEvidence.authChecks[0].resultEvidence.userIdFilters.length,0);
 assert.notEqual(analyze(input,{maxSteps:1}).status,'COMPLETE');
});
