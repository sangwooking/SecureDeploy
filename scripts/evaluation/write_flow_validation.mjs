// Authored controls. Counts refer to declared policy/link evidence, not live access.
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const {analyze}=await import(pathToFileURL(process.argv[2]));
const rows=[];
for(const layout of ['route','action'])for(const scenario of ['owner-update','open-new-update','open-old-update','owner-insert','broad-insert','owner-delete','broad-delete','public-read','missing-policy','unknown-client','external-auth','session']){
 const prefix=layout==='action'?'src/':'',file=layout==='action'?'src/app/actions.ts':'app/api/records/route.ts';
 const operation=scenario.includes('insert')?'INSERT':scenario.includes('delete')?'DELETE':scenario==='public-read'?'SELECT':'UPDATE';
 const review=['open-new-update','open-old-update','broad-insert','broad-delete'].includes(scenario);
 const unknown=['missing-policy','unknown-client','external-auth','session'].includes(scenario);
 const using=scenario==='open-old-update'||scenario==='broad-delete'||scenario==='public-read'?'true':'auth.uid()=user_id';
 const check=scenario==='open-new-update'||scenario==='broad-insert'?'true':'auth.uid()=user_id';
 const clause=operation==='INSERT'?`WITH CHECK(${check})`:operation==='UPDATE'?`USING(${using}) WITH CHECK(${check})`:`USING(${using})`;
 const sql=`CREATE TABLE public.records(id uuid,user_id uuid,title text);ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;GRANT ${operation} ON public.records TO authenticated;CREATE POLICY p ON public.records FOR ${operation} TO authenticated ${clause};`;
 const auth=scenario==='session'?"await db.auth.getSession();const user=external;":scenario==='external-auth'?"const user=await externalAuth(db);":"const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing user');";
 const action={INSERT:"insert({title:value,user_id:user.id})",UPDATE:"update({title:value}).eq('user_id',user.id)",DELETE:"delete().eq('user_id',user.id)",SELECT:"select()"}[operation];
 const source=layout==='action'?"String(input.get('title'))":"await req.text()";
 const declaration=layout==='action'?"'use server';":"";
 const fn=layout==='action'?'change(input:FormData)':'POST(req:Request)';
 const factory="import {createClient} from '@supabase/supabase-js';export function make(){const url=process.env.SERVICE_URL;const key=process.env.PUBLIC_ANON_KEY;if(!url||!key)throw new Error('missing config');return createClient(url,key);}";
 const input={files:[{filePath:prefix+'lib/client.ts',content:factory},{filePath:file,content:`${declaration}import {make} from '@/lib/client';export async function ${fn}{const value=${source};const db=${scenario==='unknown-client'?'externalFactory()':'make()'};${auth}return db.from('records').${action};}`}],
 typescriptConfigs:[{filePath:'tsconfig.json',status:'SELECTED',content:JSON.stringify({compilerOptions:{baseUrl:prefix||'.',paths:{'@/*':['*']}}})}],nodeManifests:[{filePath:'package.json',next:'15.2.0'}],
 policyFiles:scenario==='missing-policy'?[]:[{filePath:'supabase/migrations/20260101000000_records.sql',status:'SELECTED',content:sql}]};
 const r=analyze(input),repeated=analyze(input);assert.deepEqual(r,repeated);
 const s=r.supabaseAnalysis,a=s.accesses[0],e=a.authorizationEvidence;
 const hit=s.findings.some(f=>f.table===a.table&&f.operations.includes(operation));
 const warning=unknown?'UNKNOWN':review?(hit?'TP':'FN'):(hit?'FP':'TN');
 const connected=unknown?'UNKNOWN':review?(hit&&e.state==='BROAD_ACCESS_REVIEW'?'TP':'FN'):
  hit?'FP':['CONFIRMED_POLICY_EVIDENCE','PUBLIC_READ_DECLARATION'].includes(e.state)?'TN':'UNKNOWN';
 assert.equal(e.effectiveRole,'UNKNOWN');
 rows.push({caseId:layout+'-'+scenario,grade:'B',truth:unknown?'UNKNOWN':review?'DECLARED_POLICY_REVIEW':'POLICY_EVIDENCE',
  operation,warning,connected,entry:e.requestEntry,client:a.clientStatus,clientTrace:e.clientTrace,auth:e.authStatus,
  guardReferences:e.authChecks.filter(c=>c.resultEvidence).length,userIdFilters:e.authChecks.flatMap(c=>c.resultEvidence?.userIdFilters??[]),
  state:e.state,policyLocations:e.policyLocations,findings:s.findings,policyOperations:s.tables[0]?.operations??[],
  sourceEvidence:'AUTHORED_REQUEST_TEXT_OR_FORMDATA_STATIC_REVIEW_NOT_AUTOMATIC_MUTATION_ARGUMENT_TAINT',runtimeAuthorization:'UNKNOWN'});
}
const counts=key=>Object.fromEntries(['TP','FP','FN','TN','UNKNOWN'].map(v=>[v,rows.filter(r=>r[key]===v).length]));
console.log(JSON.stringify({schemaVersion:1,worker:analyze({files:[]}).analyzerVersion,scope:'AUTHORED_NEXT_WRITE_AND_DECLARED_POLICY_LINKS',independent:false,counts:{finalPolicyWarnings:counts('warning'),connectedPolicyEvidence:counts('connected')},rows}));
