// Authored Grade B local-origin contracts, not real-CVE or independent review truth.
import {pathToFileURL} from 'node:url';
const {analyze}=await import(pathToFileURL(process.argv[2]).href);
const rows=[];
for(const layout of ['route','action']){
 const action=layout==='action',input=action?"const data={title:form.get('title'),user_id:form.get('user_id'),id:form.get('id')};":"const data=await req.json();";
 const auth="const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing');";
 const scenarios=[
  ['request-owner-insert',input+"return db.from('records').insert({user_id:data.user_id});",'dataFields','user_id','REQUEST_CONTROLLED','true','REVIEW'],
  ['identity-owner-insert',auth+"return db.from('records').insert({user_id:user.id});",'dataFields','user_id','VERIFIED_USER_EVIDENCE','auth.uid()=user_id','NORMAL'],
  ['request-update-target',input+"return db.from('records').update({title:'fixed'}).eq('id',data.id);",'filters','id','REQUEST_CONTROLLED','true','REVIEW'],
  ['identity-update-target',auth+"return db.from('records').update({title:'fixed'}).eq('user_id',user.id);",'filters','user_id','VERIFIED_USER_EVIDENCE','auth.uid()=user_id','NORMAL'],
  ['request-owner-change',input+"return db.from('records').update({user_id:data.user_id});",'dataFields','user_id','REQUEST_CONTROLLED','true','REVIEW'],
  ['shared-static',"return db.from('records').insert({title:'shared'});",'dataFields','title','SERVER_CONTROLLED','true','INTENTIONALLY_SHARED'],
  ['external-auth',"const user=externalAuth();return db.from('records').insert({user_id:user.id});",'dataFields','user_id','UNKNOWN','auth.uid()=user_id','UNKNOWN'],
  ['unverified-session',"const {data:{session}}=await db.auth.getSession();return db.from('records').insert({user_id:session.user.id});",'dataFields','user_id','SESSION_UNVERIFIED','auth.uid()=user_id','UNKNOWN'],
  ['unguarded-user',"const {data:{user}}=await db.auth.getUser();return db.from('records').insert({user_id:user.id});",'dataFields','user_id','UNKNOWN','auth.uid()=user_id','UNKNOWN'],
  ['unsupported-transform',input+"return db.from('records').update({title:transform(data.title)});",'dataFields','title','UNKNOWN','auth.uid()=user_id','UNKNOWN'],
  ['delete-request',input+"return db.from('records').delete().eq('id',data.id);",'filters','id','REQUEST_CONTROLLED','true','REVIEW'],
  ['identity-delete',auth+"return db.from('records').delete().match({user_id:user.id});",'filters','user_id','VERIFIED_USER_EVIDENCE','auth.uid()=user_id','NORMAL']
 ];
 for(const [scenario,body,part,name,expected,condition,requirement] of scenarios){
  const input={files:[{filePath:action?'src/actions.ts':'app/api/records/route.ts',content:(action?"'use server';":'')+"import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.PUBLIC_ANON_KEY);"+(action?'export async function save(form:FormData){':'export async function POST(req){')+body+'}'}],nodeManifests:[{filePath:'package.json',next:'15.2.0'}],policyFiles:[{filePath:'supabase/migrations/20260101000000_records.sql',status:'SELECTED',content:`CREATE TABLE public.records(id uuid,user_id uuid,title text);ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;GRANT SELECT,INSERT,UPDATE,DELETE ON public.records TO authenticated;CREATE POLICY p ON public.records FOR ALL TO authenticated USING(${condition}) WITH CHECK(${condition});`}]};
  const s=analyze(input).supabaseAnalysis,a=s.accesses[0],w=a?.writeEvidence,observed=w?w[part].find(v=>v.name===name)?.source??'UNKNOWN':'NOT_INSPECTED';
  rows.push({caseId:layout+'-'+scenario,grade:'B',expected,observed,match:observed===expected,requirement,operation:a?.operation,
   requestEntry:a?.authorizationEvidence?.requestEntry??null,client:a?.clientStatus,policyState:a?.authorizationEvidence?.state,policyWarnings:s.findings.length,
   runtimeAuthorization:'UNKNOWN',writeEvidence:w??null});
 }
}
const counts=Object.fromEntries(['REQUEST_CONTROLLED','VERIFIED_USER_EVIDENCE','SESSION_UNVERIFIED','SERVER_CONTROLLED','UNKNOWN','NOT_INSPECTED'].map(k=>[k,rows.filter(r=>r.observed===k).length]));
console.log(JSON.stringify({schemaVersion:1,metric:'LOCAL_ORIGIN_CLASSIFICATION_NOT_VULNERABILITY_DETECTION',grade:'B',independentReview:false,targetExecuted:false,rows,counts,matches:rows.filter(r=>r.match).length,total:rows.length}));
