import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const source=(content,name='20260101000000_base.sql')=>({filePath:'supabase/migrations/'+name,status:'SELECTED',content});
const table='CREATE TABLE public.notes(id uuid,user_id uuid);ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;';
const grant='GRANT SELECT,INSERT,UPDATE,DELETE ON public.notes TO authenticated;';
const owner='CREATE POLICY own ON public.notes FOR ALL TO authenticated USING (auth.uid()=user_id) WITH CHECK(user_id=(select auth.uid()));';
const run=(sql,files=[])=>analyze({files,policyFiles:Array.isArray(sql)?sql:[source(sql)]}).supabaseAnalysis;
const op=(r,operation,role='authenticated')=>r.tables[0].operations.find(o=>o.operation===operation&&o.role===role);

test('enabled RLS, explicit grant and UID-column equality are separate declaration evidence',()=>{
  const r=run(table+grant+owner);assert.equal(r.tables[0].rls,'ENABLED');assert.equal(op(r,'UPDATE').state,'UID_COLUMN_EQUALITY');
  assert.equal(r.findings.length,0);assert.ok(r.limitations.includes('DECLARATIONS_NOT_LIVE_DATABASE'));
});
test('public read does not become a vulnerability; ownership still governs writes',()=>{
  const r=run(table+grant+owner+'CREATE POLICY reading ON public.notes FOR SELECT TO anon USING(true);GRANT SELECT ON public.notes TO anon;');
  assert.equal(op(r,'SELECT','anon').state,'ALLOW');assert.equal(r.findings.length,0);
});
test('broad writes with explicit grant produce one review-only root-cause candidate',()=>{
  const r=run(table+grant+'CREATE POLICY shared ON public.notes FOR ALL TO authenticated USING(true) WITH CHECK(true);');
  assert.equal(r.findings.length,1);assert.deepEqual(r.findings[0].operations,['INSERT','UPDATE','DELETE']);
  assert.equal(r.findings[0].priority,'REVIEW_REQUIRED');assert.equal(r.findings[0].comparisonPolicy,'NOT_COMPARED');
});
test('authentication is not ownership and condition token matches are not enough',()=>{
  const r=run(table+grant+'CREATE POLICY logged ON public.notes FOR ALL TO authenticated USING(auth.uid() IS NOT NULL);');
  assert.equal(op(r,'UPDATE').state,'AUTHENTICATION_ONLY');assert.equal(r.findings.length,1);
  const u=run(table+grant+'CREATE POLICY checkit ON public.notes USING(custom_owner_check(auth.uid(),user_id));');
  assert.equal(op(u,'UPDATE').state,'UNKNOWN');assert.equal(u.findings.length,0);
});
test('permissive OR and restrictive AND are applied for each role and command',()=>{
  const broad='CREATE POLICY broad ON public.notes FOR ALL TO authenticated USING(true);';
  assert.equal(run(table+grant+owner+broad).findings.length,1);
  const guarded=run(table+grant+broad+'CREATE POLICY guard ON public.notes AS RESTRICTIVE FOR ALL TO authenticated USING(auth.uid()=user_id);');
  assert.equal(guarded.findings.length,0);assert.equal(op(guarded,'DELETE').state,'UID_COLUMN_EQUALITY');
  assert.equal(op(run(table+grant+'CREATE POLICY guard ON public.notes AS RESTRICTIVE USING(true);'),'DELETE').state,'DENY');
});
test('UPDATE USING fallback and WITH CHECK cannot be swapped with INSERT or DELETE',()=>{
  assert.equal(run(table+grant+owner.replace(' WITH CHECK(user_id=(select auth.uid()))','')).findings.length,0);
  const r=run(table+grant+'CREATE POLICY insert_any ON public.notes FOR INSERT TO authenticated WITH CHECK(true);CREATE POLICY deleting ON public.notes FOR DELETE TO authenticated USING(auth.uid()=user_id);');
  assert.deepEqual(r.findings[0].operations,['INSERT']);assert.equal(op(r,'DELETE').state,'UID_COLUMN_EQUALITY');
});
test('ordered create/alter/rename/drop, explicit revoke and final disable are tracked',()=>{
  const first=source(table+grant+owner);
  const last=source('ALTER POLICY own ON public.notes RENAME TO limited;ALTER POLICY limited ON public.notes USING(true) WITH CHECK(true);REVOKE UPDATE ON public.notes FROM authenticated;','20260102000000_change.sql');
  const r=run([first,last]);assert.deepEqual(r.findings[0].operations,['INSERT','DELETE']);assert.equal(op(r,'UPDATE').grant,'NOT_ESTABLISHED');
  const dropped=run(table+grant+owner+'DROP POLICY own ON public.notes;');assert.equal(op(dropped,'DELETE').state,'DENY');assert.equal(dropped.findings.length,0);
  const disabled=run(table+grant+owner+'ALTER TABLE public.notes DISABLE ROW LEVEL SECURITY;');assert.equal(disabled.findings.length,1);
});
test('missing policy files and missing grants are not unsafe or verified-safe databases',()=>{
  assert.equal(run('').findings.length,0);assert.equal(run(table+'CREATE POLICY public_write ON public.notes USING(true);').findings.length,0);
  assert.equal(op(run(table),'DELETE').state,'DENY');
  assert.equal(op(run('ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;'+grant+owner),'DELETE').state,'UNKNOWN');
});
test('unqualified names, dynamic SQL, missing bases and failed parsing retain UNKNOWN',()=>{
  for(const suffix of ['DO $$ BEGIN EXECUTE query; END $$;','SET search_path=public;','ALTER POLICY missing ON public.notes USING(true);','ALTER POLICY own ON public.notes TO CURRENT_USER;']){
    const r=run(table+grant+owner+suffix);assert.equal(op(r,'DELETE').state,'UNKNOWN');assert.equal(r.findings.length,0);
  }
  const failed=run(table+"SELECT 'unterminated");assert.equal(failed.files[0].status,'PARSE_FAILED');assert.equal(failed.findings.length,0);
  const r=run('ALTER TABLE notes ENABLE ROW LEVEL SECURITY;'+table+grant+owner);assert.equal(op(r,'UPDATE').state,'UNKNOWN');
});
test('comments, SQL string data, dollar bodies and quoted identifiers are not policy instructions',()=>{
  const r=run(table+grant+owner+"SELECT 'ALTER TABLE public.notes DISABLE ROW LEVEL SECURITY;'; -- DROP POLICY own ON public.notes;\n");
  assert.equal(op(r,'UPDATE').state,'UID_COLUMN_EQUALITY');
  const quoted=run(table+grant+'CREATE POLICY p ON public.notes USING("true");');assert.equal(op(quoted,'UPDATE').state,'UNKNOWN');
});
test('empty expressions and quoted policy keywords are not trusted as broad permission syntax',()=>{
  for(const policy of ['CREATE POLICY p ON public.notes USING();','CREATE POLICY p ON public.notes AS "PERMISSIVE" USING(true);','CREATE POLICY p ON public.notes FOR "UPDATE" USING(true);']){
    const r=run(table+grant+policy);assert.equal(r.findings.length,0);assert.equal(op(r,'UPDATE').state,'UNKNOWN');
  }
});
test('source and parser budgets fail closed instead of retaining partial protection',()=>{
  const r=run([source(table+grant+owner),{filePath:'supabase/migrations/20260102000000_omitted.sql',status:'LIMIT_EXCEEDED'}]);
  assert.equal(op(r,'UPDATE').state,'UNKNOWN');assert.equal(r.findings.length,0);
});
test('function execution privileges are not table grants or a proof of helper safety',()=>{
  const r=run(table+grant+owner+'REVOKE EXECUTE ON FUNCTION public.helper() FROM PUBLIC;');
  assert.equal(op(r,'UPDATE').state,'UID_COLUMN_EQUALITY');assert.equal(r.findings.length,0);
  assert.ok(r.files[0].limitations.includes('FUNCTION_EXECUTE_PRIVILEGES_NOT_INTERPRETED'));
});
test('client origin and call site metadata are declarations, not verified sessions',()=>{
  const files=[{filePath:'src/db.ts',content:'import {createClient as init} from "@supabase/supabase-js";export const db=init(url,import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY);'},
    {filePath:'src/use.ts',content:'import {db as storage} from "./db";storage.from("notes").update({text:input}).eq("id",id);'}];
  const r=run(table+grant+owner,files);assert.equal(r.accesses[0].clientStatus,'CLIENT_DECLARATION_LINKED');
  assert.equal(r.accesses[0].policyStatus,'TABLE_DECLARATION_FOUND');assert.equal(r.accesses[0].keySource,'PUBLIC_KEY_NAME_HINT');
  assert.ok(!JSON.stringify(r).includes('VITE_SUPABASE_PUBLISHABLE_KEY'));assert.equal(r.findings.length,0);
});
test('server key hints, auth overrides, unknown aliases and custom clients never prove RLS bypass',()=>{
  const r=run('',[{filePath:'edge.ts',content:'import {createClient} from "npm:@supabase/supabase-js@2";const db=createClient(url,Deno.env.get("SERVICE_ROLE_KEY"),{global:{headers:{Authorization:request.headers.get("Authorization")}}});db.from("notes").delete();'}]);
  assert.equal(r.clients[0].keySource,'SERVER_KEY_NAME_HINT');assert.equal(r.findings.length,0);
  const u=run('',[{filePath:'route.ts',content:'context.supabase.from("notes").select("*");'}]);assert.equal(u.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
  const t=run('',[{filePath:'types.ts',content:'import type {createClient} from "@supabase/supabase-js";const db=createClient(url,key);db.from("notes").delete();'}]);assert.equal(t.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
});
