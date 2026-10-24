import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const config={filePath:'tsconfig.json',status:'SELECTED',content:'{"compilerOptions":{"paths":{"@/*":["./*"]}}}'};
const setup="import {createServerClient} from '@supabase/ssr';export function make(){const url=process.env.SERVICE_URL;const key=process.env.PUBLIC_ANON_KEY;";
const returned="return createServerClient(url,key,{cookies:{getAll(){return [];}}});}";
const guard="if(!url||!key){throw new Error('missing');}";
const run=(prefix=guard,options={})=>analyze({files:[{filePath:'lib/client.ts',content:options.factory??setup+prefix+returned},
 {filePath:'app/api/records/route.ts',content:"import {make} from '@/lib/client';export async function POST(req){const db=make();const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing user');return db.from('records')."+(options.operation??"update({title:await req.text()}).eq('user_id',user.id)")+";}"}],
 typescriptConfigs:[config],nodeManifests:[{filePath:'package.json',next:'15.2.0'}],policyFiles:options.missing?[]:[{filePath:'supabase/migrations/20260101000000_records.sql',status:'SELECTED',content:
 `CREATE TABLE public.records(user_id uuid);ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;GRANT SELECT,INSERT,UPDATE,DELETE ON public.records TO authenticated;CREATE POLICY p ON public.records FOR ALL TO authenticated USING(${options.broad?'true':'auth.uid()=user_id'}) WITH CHECK(${options.broad?'true':'auth.uid()=user_id'});`}]});

test('configuration absence throws preserve the unique Client origin, not authentication success',()=>{
 for(const prefix of [guard,"if(!url)throw new Error('missing');if(!key)throw new Error('missing');",'if((!url)||(!key)) { throw unavailable; }']){
  const s=run(prefix).supabaseAnalysis,e=s.accesses[0].authorizationEvidence;
  assert.equal(s.accesses[0].clientStatus,'CLIENT_DECLARATION_LINKED');
  assert.equal(e.state,'CONFIRMED_POLICY_EVIDENCE');assert.equal(e.effectiveRole,'UNKNOWN');
  assert.ok(e.clientTrace.some(l=>l.kind==='FACTORY_CONFIGURATION_ABSENCE_THROW'));
  assert.equal(e.authStatus,'IDENTITY_VERIFICATION_CALL_OBSERVED');assert.equal(s.findings.length,0);
 }
});
test('the same guarded origin supports read/insert/update/delete without hiding broad or missing policies',()=>{
 for(const operation of ["select()","insert({user_id:user.id})","update({})","delete().eq('user_id',user.id)"]){
  for(const options of [{},{broad:true},{missing:true}]){
   const s=run(guard,{...options,operation}).supabaseAnalysis,e=s.accesses[0].authorizationEvidence;
   assert.equal(s.accesses[0].clientStatus,'CLIENT_DECLARATION_LINKED');
   assert.equal(e.state,options.missing?'UNKNOWN':options.broad?(operation==='select()'?'PUBLIC_READ_DECLARATION':'BROAD_ACCESS_REVIEW'):'CONFIRMED_POLICY_EVIDENCE');
  }
 }
});
test('non-throwing, alternative returns, dynamic conditions and assignments cannot summarize a guarded factory',()=>{
 for(const prefix of ['if(!url)log();','if(!url)return external;','if(!url)throw unavailable;else log();','if(!check(url))throw unavailable;',
   'if(!url||external())throw unavailable;','if(!url){log();throw unavailable;}','if(!url&& !key)throw unavailable;',
   "if(!url){throw unavailable;}key=external;",'if(!url)throw unavailable;external(key);']){
  assert.equal(run(prefix).supabaseAnalysis.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN',prefix);
 }
});
test('shadowed globals, mutable values and unrelated custom configuration providers remain unknown',()=>{
 for(const factory of [setup.replace('const url=','let url=')+guard+returned,
   setup.replace("export function make(){","export function make(){const process=external;")+guard+returned,
   setup.replace('process.env.SERVICE_URL','externalConfig.url')+guard+returned,
   setup+'if('+Array(16).fill('!url').join('||')+'){throw unavailable;}'+returned]){
  const r=run(guard,{factory}).supabaseAnalysis;
  assert.equal(r.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
 }
});
