// Truth fixed before initial run; same-author validation, not independent/blind.
import {pathToFileURL} from 'node:url';
const {analyze}=await import(pathToFileURL(process.argv[2]).href);
const specs=[
 ['route-nested-payload',false,"const value=await req.json();const {owner:actor}=value;const wrapper={chosen:actor};return db.from('records').insert({user_id:wrapper.chosen});",'dataFields','user_id','REQUEST_CONTROLLED'],
 ['action-direct-object',true,"return db.from('records').insert({title:record.title});",'dataFields','title','REQUEST_CONTROLLED'],
 ['action-claims-id',true,"const claims=(await db.auth.getClaims()).data.claims;if(!claims)return;return db.from('records').insert({user_id:claims.sub});",'dataFields','user_id','VERIFIED_USER_EVIDENCE'],
 ['route-session-filter',false,"const {data:{session}}=await db.auth.getSession();if(!session)return;return db.from('records').delete().eq('user_id',session.user.id);",'filters','user_id','SESSION_UNVERIFIED'],
 ['route-custom-conversion',false,"const data=await req.json();return db.from('records').update({title:custom(data.title)});",'dataFields','title','UNKNOWN'],
 ['route-unawaited-json',false,"const data=req.json();return db.from('records').insert({title:data.title});",'dataFields','title','UNKNOWN'],
 ['route-two-payload-aliases',false,"const data={title:'constant'};const next=data;return db.from('records').update(next);",'dataFields','title','SERVER_CONTROLLED'],
 ['action-name-not-identity',true,"return db.from('records').insert({user_id:'public-display-only'});",'dataFields','user_id','SERVER_CONTROLLED']
];
const rows=specs.map(([caseId,action,body,part,name,expected])=>{
 const input={files:[{filePath:action?'actions.ts':'app/api/records/route.ts',content:(action?"'use server';":'')+"import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.PUBLIC_ANON_KEY);"+(action?'export async function save(record){':'export async function POST(req){')+body+'}'}],nodeManifests:[{filePath:'package.json',next:'15.2.0'}]};
 const r=analyze(input),w=r.supabaseAnalysis.accesses[0]?.writeEvidence,observed=w?w[part].find(v=>v.name===name)?.source??'UNKNOWN':'NOT_INSPECTED';
 return {caseId,expected,observed,match:expected===observed,writeEvidence:w??null};
});
console.log(JSON.stringify({metric:'LOCAL_ORIGIN_CLASSIFICATION_NOT_VULNERABILITY_DETECTION',grade:'B',split:'SAME_AUTHOR_VALIDATION_NOT_INDEPENDENT_BLIND',truthFixedBeforeRun:true,implementationChangedAfterResult:false,total:rows.length,matches:rows.filter(r=>r.match).length,rows}));
