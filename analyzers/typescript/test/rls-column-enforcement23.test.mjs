import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const base='CREATE TABLE public.records(id integer,actor uuid,content text,classification text);ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;';
const policy=(condition='true')=>`CREATE POLICY p ON public.records TO authenticated USING(${condition}) WITH CHECK(${condition});`;
const run=(sql,extra=[])=>analyze({files:[],policyFiles:[{filePath:'supabase/migrations/001_records.sql',status:'SELECTED',content:base+sql},...extra]}).supabaseAnalysis;
const update=s=>s.tables[0].operations.find(o=>o.role==='authenticated'&&o.operation==='UPDATE');
test('column-only UPDATE is a write capability, never a whole-table grant or protected-field verdict',()=>{
 const s=run('GRANT SELECT,UPDATE(content) ON public.records TO authenticated;'+policy());
 assert.equal(s.analyzerVersion,'supabase-rls-v4');assert.equal(update(s).candidate,true);
 assert.equal(update(s).grant,'EXPLICIT_GRANT');
 const acl=s.tables[0].updatePrivileges.find(p=>p.role==='authenticated');
 assert.equal(acl.tableGrant,'NOT_ESTABLISHED');assert.deepEqual(acl.columns,['content']);
 assert.equal(s.findings.length,1);assert.equal(s.findings[0].priority,'REVIEW_REQUIRED');
 assert.equal(s.findings[0].comparisonPolicy,'NOT_COMPARED');
 assert.match(s.findings[0].recommendation,/확정 SQL 패치가 아닙니다/);
});
test('PUBLIC column grants add to direct grants and revocation preserves independent sources',()=>{
 const s=run('GRANT UPDATE(content) ON public.records TO PUBLIC;REVOKE UPDATE(content) ON public.records FROM authenticated;'+policy());
 assert.equal(update(s).candidate,true);
 const no=run('GRANT UPDATE(content) ON public.records TO authenticated;REVOKE UPDATE ON public.records FROM authenticated;'+policy());
 assert.equal(update(no).candidate,false);assert.equal(update(no).grant,'NOT_ESTABLISHED');
});
test('owner predicates, no permissive policy and restrictive guards retain their separate meaning',()=>{
 const grant='GRANT SELECT,UPDATE(content) ON public.records TO authenticated;';
 assert.equal(update(run(grant+policy('actor=auth.uid()'))).candidate,false);
 assert.equal(update(run(grant+'CREATE POLICY p ON public.records AS RESTRICTIVE USING(true);')).state,'DENY');
 const r=run(grant+policy()+'CREATE POLICY guard ON public.records AS RESTRICTIVE TO authenticated USING(actor=auth.uid()) WITH CHECK(actor=auth.uid());');
 assert.equal(update(r).candidate,false);assert.equal(update(r).state,'UID_COLUMN_EQUALITY');
});
test('unsupported role state, helper policy and uninspected SQL remain unknown despite a column grant',()=>{
 for(const tail of ['GRANT writers TO authenticated;','DO $$BEGIN NULL;END$$;']){
  const s=run('GRANT UPDATE(content) ON public.records TO authenticated;'+policy()+tail);
  assert.equal(update(s).state,'UNKNOWN');assert.equal(update(s).candidate,false);
 }
 const s=run('GRANT UPDATE(content) ON public.records TO authenticated;'+policy('external_check(actor)'));
 assert.equal(update(s).state,'UNKNOWN');assert.equal(update(s).candidate,false);
 const missing=run('GRANT UPDATE(content) ON public.records TO authenticated;'+policy(),[{filePath:'supabase/migrations/002_missing.sql',status:'NOT_RUN'}]);
 assert.equal(update(missing).state,'UNKNOWN');assert.equal(update(missing).candidate,false);
});
test('column capability does not imply SELECT or other write capabilities',()=>{
 const s=run('GRANT UPDATE(content) ON public.records TO authenticated;'+policy());
 assert.equal(update(s).candidate,true);
 for(const operation of ['SELECT','INSERT','DELETE'])assert.equal(s.tables[0].operations.find(o=>o.role==='authenticated'&&o.operation===operation).grant,'NOT_ESTABLISHED');
 assert.equal(s.tables[0].updatePrivileges[1].tableGrant,'NOT_ESTABLISHED');
});
