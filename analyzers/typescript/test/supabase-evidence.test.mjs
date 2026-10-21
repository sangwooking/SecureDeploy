import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const policy=(condition='auth.uid()=user_id')=>({filePath:'supabase/migrations/20260101000000_notes.sql',status:'SELECTED',content:
  `CREATE TABLE public.notes(id uuid,user_id uuid);ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;GRANT SELECT,INSERT,UPDATE,DELETE ON public.notes TO authenticated;CREATE POLICY own ON public.notes FOR ALL TO authenticated USING(${condition}) WITH CHECK(${condition});`});
const file=(filePath,content)=>({filePath,content});
const run=(files,condition)=>analyze({files,policyFiles:[policy(condition)],nodeManifests:[{filePath:'package.json',next:'15.2.0'}]}).supabaseAnalysis;

test('relative factory and immutable object alias connect a Next route to repository ownership evidence',()=>{
  const r=run([file('lib/client.ts',"import {createServerClient} from '@supabase/ssr';export function make(){return createServerClient('https://example.invalid',process.env.PUBLIC_ANON_KEY,{cookies:{getAll(){return []},setAll(values){}}});}"),
    file('app/api/notes/route.ts',"import {make} from '../../../lib/client';export async function GET(req){const db=make();const services={db};return Response.json(await services.db.from('notes').select());}")]);
  assert.equal(r.accesses[0].clientStatus,'CLIENT_DECLARATION_LINKED');
  assert.equal(r.accesses[0].authorizationEvidence.state,'CONFIRMED_POLICY_EVIDENCE');
  assert.equal(r.accesses[0].authorizationEvidence.authStatus,'SESSION_REFERENCE_UNVERIFIED');
  assert.equal(r.findings.length,0);
});
test('public reads are not broad-write vulnerabilities and broad writes remain declaration review',()=>{
  const code="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);db.from('notes').select();db.from('notes').update({});";
  const r=run([file('data.ts',code)],'true');
  assert.equal(r.accesses[0].authorizationEvidence.state,'PUBLIC_READ_DECLARATION');
  assert.equal(r.accesses[1].authorizationEvidence.state,'BROAD_ACCESS_REVIEW');
  assert.equal(r.findings.length,1);
});
test('getSession and awaited identity verification calls are distinct, neither proves resource authorization',()=>{
  for(const [method,status]of [['getSession','SESSION_READ_UNVERIFIED'],['getUser','IDENTITY_VERIFICATION_CALL_OBSERVED'],['getClaims','IDENTITY_VERIFICATION_CALL_OBSERVED']]){
    const r=run([file('supabase/functions/notes/index.ts',`import {createClient} from '@supabase/supabase-js';Deno.serve(async(req)=>{const db=createClient('https://example.invalid',Deno.env.get('ANON_KEY'));await db.auth.${method}();return Response.json(await db.from('notes').select());});`)]);
    const e=r.accesses[0].authorizationEvidence;assert.equal(e.authStatus,status);assert.equal(e.effectiveRole,'UNKNOWN');
    assert.equal(e.authChecks[0].method,method);assert.ok(e.limitations.includes('AUTH_CALL_NOT_SUCCESS_OR_AUTHORIZATION_PROOF'));
  }
});
test('dynamic Proxy, unknown factory and mutable clients remain unknown',()=>{
  for(const init of ["new Proxy({}, {get(){return external;}})",'externalFactory()','external']){
    const r=run([file('data.ts',`const db=${init};db.from('notes').select();`)]);
    assert.equal(r.accesses[0].authorizationEvidence.state,'UNKNOWN');
    assert.equal(r.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
  }
});
test('unique local argument origins connect, conflicting call sites do not',()=>{
  const prefix="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);function rows(client){return client.from('notes').select();}";
  assert.equal(run([file('data.ts',prefix+'rows(db);')]).accesses[0].clientStatus,'CLIENT_DECLARATION_LINKED');
  assert.equal(run([file('data.ts',prefix+'rows(db);rows(external);')]).accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
});
test('official Edge context separates a user JWT declaration from privileged data access',()=>{
  const content="import {withSupabase} from 'npm:@supabase/server@1';export default {fetch:withSupabase({auth:'user'},async(req,ctx)=>{await ctx.supabase.from('notes').select();return Response.json(await ctx.supabaseAdmin.from('notes').delete());})};";
  const r=run([file('supabase/functions/notes/index.ts',content)]);
  assert.equal(r.accesses[0].authorizationEvidence.authStatus,'USER_JWT_WRAPPER_DECLARATION');
  assert.equal(r.accesses[1].authorizationEvidence.state,'ADMIN_ACCESS_REVIEW');
  assert.equal(r.accesses[1].authorizationEvidence.effectiveRole,'UNKNOWN');
  assert.equal(r.clients.length,2);
  assert.equal(r.findings.length,0); // Missing application checks alone are not a proven vulnerability.
  const shadowed=run([file('edge.ts',content.replace("await ctx.supabase.from('notes').select();","{const ctx=unknown;await ctx.supabase.from('notes').select();}"))]);
  assert.equal(shadowed.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
  const service=run([file('edge.ts',content.replace("auth:'user'","auth:'secret'"))]);
  assert.equal(service.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
});
test('unproven schema, options and custom transport cannot claim matching ownership protection',()=>{
  for(const options of ["{db:{schema:'private'}}",'{db:external}', 'external','{global:{fetch:external}}','{...external}']){
    const r=run([file('data.ts',`import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY,${options});db.from('notes').select();`)]);
    assert.equal(r.accesses[0].authorizationEvidence.state,'UNKNOWN');
  }
});
test('a broad anonymous write is not concealed by an authenticated ownership policy',()=>{
  const sql=policy();sql.content+='GRANT UPDATE ON public.notes TO anon;CREATE POLICY broad ON public.notes FOR UPDATE TO anon USING(true);';
  const r=analyze({files:[file('data.ts',"import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);db.from('notes').update({});")],policyFiles:[sql]}).supabaseAnalysis;
  assert.equal(r.accesses[0].authorizationEvidence.state,'BROAD_ACCESS_REVIEW');
});
test('partial migrations preserve UNKNOWN and key values never enter authorization evidence',()=>{
  const key='sb_secret_synthetic_not_a_real_key';
  const r=analyze({files:[file('data.ts',`import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid','${key}');db.from('notes').delete();`)],
    policyFiles:[policy(),{filePath:'supabase/migrations/20260102000000_later.sql',status:'LIMIT_EXCEEDED'}]}).supabaseAnalysis;
  assert.equal(r.accesses[0].authorizationEvidence.state,'UNKNOWN');assert.ok(!JSON.stringify(r).includes(key));
});
test('escaped objects and post-call mutations do not inherit ownership protection',()=>{
  for(const extra of ['external(bag);','external({wrapped:bag});','bag.db=external;']){
    const r=run([file('data.ts',`import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);const bag={db};${extra}bag.db.from('notes').select();`)]);
    assert.equal(r.accesses[0].authorizationEvidence.state,'UNKNOWN');
  }
});
test('writes through immutable aliases invalidate a protection claim without erasing legacy declarations',()=>{
  const r=run([file('data.ts',"import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);const alias=db;alias.from=external;db.from('notes').select();")]);
  assert.equal(r.clients.length,1);assert.equal(r.accesses[0].authorizationEvidence.state,'UNKNOWN');
});
