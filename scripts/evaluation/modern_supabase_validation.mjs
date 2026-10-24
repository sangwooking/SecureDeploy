// Authored Grade B controls, not real CVEs or an independent security review.
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const {analyze}=await import(pathToFileURL(process.argv[2]));
const rows=[];
for(const layout of ['root','src'])for(const scenario of ['broad','owner','public','session','external']){
  const prefix=layout==='src'?'src/':'',method=scenario==='public'?'select()':'update({})';
  const condition=scenario==='broad'?'true':'auth.uid()=user_id';
  const permission=scenario==='public'?"CREATE POLICY p ON public.items FOR SELECT TO authenticated USING(true);":`CREATE POLICY p ON public.items FOR ALL TO authenticated USING(${condition}) WITH CHECK(${condition});`;
  const guard=scenario==='session'?"await db.auth.getSession();":scenario==='external'?"const user=await customAuth(db);":"const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing');";
  const ending=scenario==='external'?"const db=externalFactory();":"const db=await make();";
  const input={files:[{filePath:prefix+'lib/client.ts',content:"import {createServerClient} from '@supabase/ssr';export function make(){const jar=cookies();return createServerClient('https://example.invalid',process.env.PUBLIC_ANON_KEY,{cookies:{getAll(){return jar.getAll();}}});}"},
    {filePath:prefix+'app/api/items/route.ts',content:`import {make} from '~/lib/client';export async function POST(){${ending}${guard}return Response.json(await db.from('items').${method});}`}],
    typescriptConfigs:[{filePath:'tsconfig.json',status:'SELECTED',content:JSON.stringify({compilerOptions:{baseUrl:prefix||'.',paths:{'~/*':['*']}}})}],
    nodeManifests:[{filePath:'package.json',next:'15.2.0'}],policyFiles:[{filePath:'supabase/migrations/20260101000000_items.sql',status:'SELECTED',content:`CREATE TABLE public.items(user_id uuid);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;GRANT SELECT,UPDATE ON public.items TO authenticated;${permission}`}]};
  const before=analyze(input),again=analyze({...input,files:[...input.files].reverse()});
  const normalize=r=>({...r,files:[...r.files].sort((a,b)=>a.filePath.localeCompare(b.filePath))});
  assert.deepEqual(normalize(before),normalize(again));
  const s=before.supabaseAnalysis,a=s.accesses[0],e=a.authorizationEvidence;
  const targetFindings=s.findings.filter(f=>f.table==='public.items'||f.table==='items');
  const truth=scenario==='broad'?'REVIEW_CANDIDATE':scenario==='external'?'UNKNOWN':'POLICY_EVIDENCE';
  const observed=e.state==='BROAD_ACCESS_REVIEW'&&targetFindings.length?'TP':truth==='REVIEW_CANDIDATE'?'FN':
    truth==='UNKNOWN'?'UNKNOWN':targetFindings.length?'FP':['CONFIRMED_POLICY_EVIDENCE','PUBLIC_READ_DECLARATION'].includes(e.state)?'TN':'UNKNOWN';
  rows.push({caseId:`${layout}-${scenario}`,truth,observed,client:a.clientStatus,policyState:e.state,authStatus:e.authStatus,
    resultGuards:e.authChecks.filter(c=>c.resultEvidence).length,directNextDeclaration:!!e.requestEntry,findings:targetFindings.length,
    guardExpectation:scenario==='session'||scenario==='external'?'NONE':'LOCAL_OBSERVATION_ONLY'});
}
console.log(JSON.stringify({schemaVersion:1,grade:'B',independent:false,metric:'CONNECTED_POLICY_CLASSIFICATION_NOT_NEW_CVE_DETECTION',worker:analyze({files:[]}).analyzerVersion,
  targetExecuted:false,paidAiCalls:0,rows,counts:Object.fromEntries(['TP','FP','FN','TN','UNKNOWN'].map(k=>[k,rows.filter(r=>r.observed===k).length]))}));
