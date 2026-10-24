import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const config=content=>({filePath:'tsconfig.json',status:'SELECTED',content});
const paths=config('{"compilerOptions":{"paths":{"@/*":["./*"]}}}');
const factory={filePath:'lib/client.ts',content:"import {createServerClient} from '@supabase/ssr';export async function make(){const cookies=externalCookies();return createServerClient('https://example.invalid',process.env.PUBLIC_ANON_KEY,{cookies:{getAll(){return cookies.getAll();}}});}"};
const sql=condition=>({filePath:'supabase/migrations/20260101000000_items.sql',status:'SELECTED',content:`CREATE TABLE public.items(id uuid,user_id uuid);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;GRANT SELECT,UPDATE ON public.items TO authenticated;CREATE POLICY own ON public.items FOR ALL TO authenticated USING(${condition}) WITH CHECK(${condition});`});
function run(code,configs=[paths],condition='auth.uid()=user_id',extra=[]){return analyze({files:[factory,{filePath:'app/api/items/route.ts',content:`import {make} from '@/lib/client';export async function GET(req){const db=await make();${code}}`},...extra],typescriptConfigs:configs,nodeManifests:[{filePath:'package.json',next:'15.2.0'}],policyFiles:[sql(condition)]});}
test('static JSONC aliases reuse existing SSR factory and distinguish ownership from broad writes',()=>{
  for(const [condition,state,count] of [['auth.uid()=user_id','CONFIRMED_POLICY_EVIDENCE',0],['true','BROAD_ACCESS_REVIEW',1]]){
    const r=run("return Response.json(await db.from('items').update({}));",[config('{/* static */"compilerOptions":{"baseUrl":".","paths":{"@/*":["./*"]},},}')],condition);
    assert.equal(r.supabaseAnalysis.accesses[0].clientStatus,'CLIENT_DECLARATION_LINKED');
    assert.equal(r.supabaseAnalysis.accesses[0].authorizationEvidence.state,state);
    assert.equal(r.supabaseAnalysis.findings.length,count);
    assert.equal(r.files.find(f=>f.filePath==='app/api/items/route.ts').entrypoints,1);
  }
});
test('extends, duplicate keys, multiple targets, workspace escape and omitted alias sources remain unknown',()=>{
  for(const c of ['{"extends":"./external.json","compilerOptions":{"paths":{"@/*":["./*"]}}}',
    '{"compilerOptions":{"paths":{"@/*":["./*"]},"paths":{"@/*":["./lib/*"]}}}',
    '{"compilerOptions":{"paths":{"@/*":["./*","./fallback/*"]}}}',
    '{"compilerOptions":{"paths":{"@/*":["../*"]}}}']){
    const r=run("return db.from('items').select();",[config(c)]);
    assert.equal(r.supabaseAnalysis.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
    assert.equal(r.supabaseAnalysis.accesses[0].authorizationEvidence.state,'UNKNOWN');
  }
});
test('a local alias cannot masquerade as the official Supabase SDK',()=>{
  const r=analyze({files:[{filePath:'app/api/items/route.ts',content:"import {createClient} from '@supabase/supabase-js';const db=createClient('fixed','fixed');export async function GET(){return db.from('items').select();}"},
    {filePath:'fake.ts',content:'export function createClient(){return external;}'}],typescriptConfigs:[config('{"compilerOptions":{"paths":{"@supabase/supabase-js":["./fake.ts"]}}}')],policyFiles:[sql('auth.uid()=user_id')]});
  assert.equal(r.supabaseAnalysis.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
});
test('Next source-to-fetch module flow reuses aliases without extending call-depth or executing a module',()=>{
  const r=analyze({files:[{filePath:'app/api/run/route.ts',content:"import {send} from '@/lib/send';export async function POST(req){return send(new URL(req.url).searchParams.get('url'));}"},
    {filePath:'lib/send.ts',content:'export function send(value){return fetch(value);}'}],typescriptConfigs:[paths],nodeManifests:[{filePath:'package.json',next:'15.2.0'}]});
  assert.equal(r.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH').length,1);
});
test('getUser/getClaims absence exits and matching ID filters are observations, never authentication success',()=>{
  for(const [method,value,field] of [['getUser','user','id'],['getClaims','claims','sub']]){
    const r=run(`const {data:{${value}}}=await db.auth.${method}();if(!${value})return Response.json({error:true});return Response.json(await db.from('items').select().eq('user_id',${value}.${field}));`);
    const e=r.supabaseAnalysis.accesses[0].authorizationEvidence;
    assert.equal(e.authStatus,'IDENTITY_VERIFICATION_CALL_OBSERVED');assert.equal(e.effectiveRole,'UNKNOWN');
    assert.equal(e.authChecks[0].resultEvidence.status,'IDENTITY_RESULT_GUARD_OBSERVED');
    assert.equal(e.authChecks[0].resultEvidence.userIdFilters.length,1);
  }
});
test('property result and throw guard support a local helper without claiming HTTP invocation',()=>{
  const r=run("const user=(await db.auth.getUser()).data.user;if(!user){throw new Error('missing');}return db.from('items').select().eq('user_id',user.id);");
  assert.equal(r.supabaseAnalysis.accesses[0].authorizationEvidence.authChecks[0].resultEvidence.userIdFilters.length,1);
});
test('session reads, ignored results, wrong identity, mutations and non-exiting checks do not gain result evidence',()=>{
  const tails=["await db.auth.getSession();return db.from('items').select();",
    "await db.auth.getUser();return db.from('items').select();",
    "const {data:{user}}=await db.auth.getUser();if(!user)log();return db.from('items').select();",
    "const {data:{user}}=await db.auth.getUser();if(!other)throw new Error('missing');return db.from('items').select();",
    "const {data:{user}}=await db.auth.getUser();if(!user)return;external(user);return db.from('items').select().eq('user_id',user.id);",
    "let user=(await db.auth.getUser()).data.user;user=external;if(!user)return;return db.from('items').select();",
    "const user=(await db.auth.getUser()).data.user;user.id++;if(!user)return;return db.from('items').select().eq('user_id',user.id);",
    "const user=(await db.auth.getUser()).data.user;delete user.id;if(!user)return;return db.from('items').select().eq('user_id',user.id);"];
  for(const tail of tails){const e=run(tail).supabaseAnalysis.accesses[0].authorizationEvidence;assert.ok(e.authChecks.every(c=>!c.resultEvidence),tail);}
});
test('nearest omitted or unsupported config cannot inherit a more permissive root alias',()=>{
  for(const nested of [{filePath:'app/tsconfig.json',status:'LIMIT_EXCEEDED'},config('{"compilerOptions":null}'),config('{"compilerOptions":{"paths":null}}')]){
    const configs=nested.filePath==='app/tsconfig.json'?[paths,nested]:[nested];
    assert.equal(run("return db.from('items').select();",configs).supabaseAnalysis.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
  }
});
test('ambiguous extensions and unselected targets stay unknown, independent of input order',()=>{
  const code="return db.from('items').select();";
  const extras=[{filePath:'lib/client.js',content:factory.content}];
  assert.equal(run(code,[paths],'auth.uid()=user_id',extras).supabaseAnalysis.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
  const input={files:[{filePath:'app/api/a/route.ts',content:"import {make} from '@/lib/client';export async function GET(){const db=await make();return db.from('items').select();}"}],typescriptConfigs:[paths],nodeSourceInventory:['lib/client.ts','tsconfig.json']};
  assert.equal(analyze(input).supabaseAnalysis.accesses[0].clientStatus,'CLIENT_ORIGIN_UNKNOWN');
  const files=[factory,{filePath:'app/api/a/route.ts',content:input.files[0].content}];
  const a=analyze({...input,files}),b=analyze({...input,files:[...files].reverse()});
  assert.deepEqual(a.supabaseAnalysis.accesses,b.supabaseAnalysis.accesses);
});
test('src baseUrl and direct request association do not turn helper observations into requests',()=>{
  const r=analyze({files:[{...factory,filePath:'src/lib/client.ts'},
    {filePath:'src/app/api/a/route.ts',content:"import {make} from '~/lib/client';export async function GET(){const db=await make();const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing');return db.from('items').select().eq('user_id',user.id);}"},
    {filePath:'src/lib/helper.ts',content:"import {make} from '~/lib/client';export async function helper(){const db=await make();const {data:{user}}=await db.auth.getUser();if(!user)return;return db.from('items').select().eq('user_id',user.id);}"}],
    typescriptConfigs:[config('{"compilerOptions":{"baseUrl":"src","paths":{"~/*":["*"]}}}')],nodeManifests:[{filePath:'package.json',next:'15.2.0'}]});
  const direct=r.supabaseAnalysis.accesses.find(a=>a.location.filePath.includes('/app/'));
  const helper=r.supabaseAnalysis.accesses.find(a=>a.location.filePath.endsWith('helper.ts'));
  assert.equal(direct.authorizationEvidence.requestEntry.kind,'NEXT_ROUTE_HANDLER');
  assert.ok(helper.authorizationEvidence.authChecks[0].resultEvidence);
  assert.ok(!helper.authorizationEvidence.requestEntry);
});
test('file-scoped Server Function evidence is a declaration, not an invocation or auth guarantee',()=>{
  const r=analyze({files:[factory,{filePath:'app/actions.ts',content:"'use server';import {make} from '@/lib/client';export async function change(){const db=await make();const {data:{claims}}=await db.auth.getClaims();if(!claims)return;return db.from('items').update({}).eq('user_id',claims.sub);}"}],typescriptConfigs:[paths],nodeManifests:[{filePath:'package.json',next:'15.2.0'}]});
  const e=r.supabaseAnalysis.accesses[0].authorizationEvidence;
  assert.equal(e.requestEntry.kind,'NEXT_SERVER_FUNCTION');
  assert.equal(e.authChecks[0].resultEvidence.userIdFilters.length,1);
  assert.equal(e.effectiveRole,'UNKNOWN');
});
