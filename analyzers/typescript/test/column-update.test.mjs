import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const run=(acl,{payload='{level:body.level}',tail='',missing=false}={})=>analyze({files:[{filePath:'app/api/items/route.ts',content:`import {createClient} from '@supabase/supabase-js';const db=createClient('url',process.env.ANON_KEY);export async function POST(req){const body=await req.json();return db.from('items').update(${payload}).eq('id',body.id);}`}],nodeManifests:[{filePath:'package.json',next:'15.2.0'}],policyFiles:[{filePath:'supabase/migrations/20260201000000_items.sql',status:'SELECTED',content:`CREATE TABLE public.items(id integer,level text,label text);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;${acl}CREATE POLICY p ON public.items FOR UPDATE TO authenticated USING(true) WITH CHECK(true);${tail}`},...(missing?[{filePath:'supabase/migrations/20260202000000_missing.sql',status:'NOT_RUN'}]:[])]}).supabaseAnalysis;
const acl=s=>s.accesses[0].writeEvidence.columnUpdate;
const field=s=>acl(s).roles.find(r=>r.role==='authenticated').fields[0].grant;
test('table grants survive column revocation but table revocation clears earlier column grants',()=>{
 assert.equal(field(run('GRANT UPDATE ON public.items TO authenticated;REVOKE UPDATE(level) ON public.items FROM authenticated;')),'TABLE_GRANT');
 assert.equal(field(run('GRANT UPDATE(level) ON public.items TO authenticated;REVOKE UPDATE ON public.items FROM authenticated;')),'NOT_ESTABLISHED');
 assert.equal(field(run('REVOKE UPDATE ON public.items FROM authenticated;GRANT UPDATE(level) ON public.items TO authenticated;')),'COLUMN_GRANT');
});
test('PUBLIC and direct privileges add, and revoking one source does not erase the other',()=>{
 assert.equal(field(run('GRANT UPDATE ON public.items TO public;REVOKE UPDATE ON public.items FROM authenticated;')),'TABLE_GRANT');
 assert.equal(field(run('GRANT UPDATE(level) ON public.items TO public;REVOKE UPDATE(level) ON public.items FROM authenticated;')),'COLUMN_GRANT');
 assert.equal(field(run('GRANT UPDATE(level) ON public.items TO authenticated;GRANT UPDATE ON public.items TO public;REVOKE UPDATE ON public.items FROM public;')),'COLUMN_GRANT');
});
test('column updates are per field, not a row ownership or protected-property verdict',()=>{
 const s=run('GRANT SELECT,UPDATE(label) ON public.items TO authenticated;',{payload:'{level:body.level,label:body.label}'});
 assert.deepEqual(acl(s).roles[1].fields.map(f=>f.grant),['NOT_ESTABLISHED','COLUMN_GRANT']);
 assert.ok(acl(s).limitations.includes('PROTECTED_PROPERTY_REQUIREMENTS_UNKNOWN'));
 assert.equal(s.accesses[0].authorizationEvidence.effectiveRole,'UNKNOWN');assert.equal(s.findings.length,0);
});
test('valid column REVOKE no longer hides an existing broad table write review candidate',()=>{
 const s=run('GRANT UPDATE ON public.items TO authenticated;REVOKE UPDATE(level) ON public.items FROM authenticated;');
 assert.equal(s.findings.length,1);assert.equal(s.findings[0].priority,'REVIEW_REQUIRED');assert.equal(s.findings[0].comparisonPolicy,'NOT_COMPARED');
});
test('inheritance, dynamic SQL, missing sources, unsupported column verbs and quoted PUBLIC remain unknown',()=>{
 for(const a of ['GRANT UPDATE ON public.items TO writers;GRANT writers TO authenticated;','GRANT SELECT(level) ON public.items TO authenticated;','GRANT INSERT(level) ON public.items TO authenticated;','GRANT DELETE(level) ON public.items TO authenticated;','GRANT UPDATE ON public.items TO "public";','GRANT UPDATE ON public.items TO CURRENT_USER;','GRANT UPDATE ON public.items TO authenticated WITH GRANT OPTION;'])assert.equal(field(run(a)),'UNKNOWN',a);
 for(const opts of [{tail:'DO $$BEGIN NULL;END$$;'}, {missing:true}, {payload:'{...body}'}])assert.equal(acl(run('GRANT UPDATE ON public.items TO authenticated;',opts)).status,'UNKNOWN');
});
test('quoted column case, mixed verbs and migration order are deterministic',()=>{
 assert.equal(field(run('GRANT SELECT, UPDATE("level", label) ON TABLE public.items TO authenticated;')),'COLUMN_GRANT');
 assert.equal(field(run('GRANT UPDATE("Level") ON public.items TO authenticated;')),'NOT_ESTABLISHED');
 assert.equal(field(run('GRANT ALL PRIVILEGES ON public.items TO authenticated;REVOKE UPDATE(level) ON public.items FROM authenticated;')),'TABLE_GRANT');
});
test('new column state is bounded and unsupported overflow never confirms privileges',()=>{
 const cols=Array.from({length:65},(_,i)=>'c'+i).join(',');
 assert.equal(field(run(`GRANT UPDATE(${cols}) ON public.items TO authenticated;`)),'UNKNOWN');
});
