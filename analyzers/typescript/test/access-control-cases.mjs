// Authored evidence contracts, not runtime authorization or independent CVE truth.
export function accessInput(body,{action=false,policy='auth.uid()=holder',extra=''}={}){
 const head="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.PUBLIC_ANON_KEY);";
 return {files:[{filePath:action?'app/actions.ts':'app/api/records/route.ts',content:(action?"'use server';":'')+head+extra+
  (action?'export async function change(input){':'export async function POST(req){')+body+'}'}],nodeManifests:[{filePath:'package.json',next:'15.2.0'}],
  policyFiles:[{filePath:'supabase/migrations/20260101000000_records.sql',status:'SELECTED',content:`CREATE TABLE public.records(id uuid,holder uuid,title text);ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;GRANT SELECT,INSERT,UPDATE,DELETE ON public.records TO authenticated;CREATE POLICY own ON public.records FOR ALL TO authenticated USING(${policy}) WITH CHECK(${policy});`}]};
}
const auth="const {data:{user}}=await db.auth.getUser();if(!user)return;";
const c=(id,expected,body,options={})=>({id,expected,input:accessInput(body,options)});
export const accessCases=[
 c('direct-read',1,auth+"return db.from('records').select().eq('holder',user.id);"),
 c('alias-read',1,auth+"const identity=user.id;return db.from('records').select().eq('holder',identity);"),
 c('destructure-read',1,auth+"const {id:identity}=user;return db.from('records').select().eq('holder',identity);"),
 c('match-read',1,auth+"return db.from('records').select().match({holder:user.id});"),
 c('match-alias-update',1,auth+"const identity=user.id;return db.from('records').update({title:'fixed'}).match({holder:identity});"),
 c('match-shorthand-delete',1,auth+"const holder=user.id;return db.from('records').delete().match({holder});"),
 c('match-claims',1,"const {data:{claims}}=await db.auth.getClaims();if(!claims)throw new Error('missing');const identity=claims.sub;return db.from('records').select().match({holder:identity});"),
 c('action-alias',1,auth+"const identity=user.id;return db.from('records').delete().eq('id',input.id).eq('holder',identity);",{action:true}),
 c('body-object-and-identity',1,"const body=await req.json();"+auth+"const identity=user.id;return db.from('records').update({title:'fixed'}).eq('id',body.id).eq('holder',identity);"),
 {...c('two-identity-filters',2,auth+"return db.from('records').select().eq('holder',user.id).match({holder:user.id});"),observedExpected:1,knownGap:'Earlier argument escape remains conservative; second filter is not confirmed.'},
 c('authentication-without-object-scope',0,auth+"const body=await req.json();return db.from('records').delete().eq('id',body.id);"),
 c('request-id-not-identity',0,auth+"const body=await req.json();const identity=body.id;return db.from('records').select().eq('holder',identity);"),
 c('other-user-not-identity',0,auth+"const other={id:'fixed'};return db.from('records').select().match({holder:other.id});"),
 c('session-not-verified',0,"const {data:{session}}=await db.auth.getSession();if(!session)return;return db.from('records').select().match({holder:session.user.id});"),
 c('no-exit',0,"const {data:{user}}=await db.auth.getUser();if(!user){}const identity=user.id;return db.from('records').select().match({holder:identity});"),
 c('identity-reassigned',0,auth+"let identity=user.id;identity='fixed';return db.from('records').select().eq('holder',identity);"),
 c('identity-mutated',0,auth+"user.id='fixed';return db.from('records').select().match({holder:user.id});"),
 c('external-authorization',0,"const user=externalAuth();return db.from('records').select().match({holder:user.id});"),
 c('match-spread',0,auth+"return db.from('records').select().match({holder:user.id,...external});"),
 c('match-duplicate',0,auth+"return db.from('records').select().match({holder:user.id,holder:'fixed'});"),
 c('match-dynamic',0,auth+"return db.from('records').select().match({[field]:user.id});"),
 c('match-object-alias',0,auth+"const filter={holder:user.id};return db.from('records').select().match(filter);"),
 c('public-read-intent-not-inferred',0,"return db.from('records').select();",{policy:'true'}),
 c('shared-intent-not-inferred',0,auth+"return db.from('records').update({title:'fixed'});",{policy:'true'}),
 c('admin-name-not-proof',0,"const isAdmin=externalRole();if(!isAdmin)return;return db.from('records').delete();"),
 c('client-only-check',0,"return db.from('records').update({title:'fixed'});",{extra:"function ClientOnly(){return loggedIn?'edit':null;}"}),
];
