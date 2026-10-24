import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const head="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.PUBLIC_ANON_KEY);";
export function run(body,{action=false,extra='',policy='true',files=[]}={}){
 const filePath=action?'src/actions.ts':'app/api/items/route.ts';
 return analyze({files:[{filePath,content:(action?"'use server';":'')+head+extra+(action?'export async function save(form:FormData, input){':'export async function POST(req,context){')+body+'}'},...files],
 nodeManifests:[{filePath:'package.json',next:'15.2.0'}],policyFiles:[{filePath:'supabase/migrations/20260101000000_items.sql',status:'SELECTED',content:`CREATE TABLE public.items(id uuid,user_id uuid,title text);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;GRANT SELECT,INSERT,UPDATE,DELETE ON public.items TO authenticated;CREATE POLICY p ON public.items FOR ALL TO authenticated USING(${policy}) WITH CHECK(${policy});`}]});
}
const write=r=>r.supabaseAnalysis.accesses[0].writeEvidence;
const field=(r,name)=>write(r).dataFields.find(f=>f.name===name)?.source;

test('Server Function FormData conversions reach write fields separately from row filters',()=>{
 const r=run("const title=String(form.get('title')??'').trim();const id=Number(form.get('id'));const active=form.get('active')==='yes';return db.from('items').update({title,active:!active,fixed:7}).eq('id',id);",{action:true});
 assert.equal(field(r,'title'),'REQUEST_CONTROLLED');assert.equal(field(r,'active'),'REQUEST_CONTROLLED');assert.equal(field(r,'fixed'),'SERVER_CONTROLLED');
 assert.equal(write(r).filters[0].source,'REQUEST_CONTROLLED');assert.equal(write(r).filters[0].name,'id');
 assert.equal(r.supabaseAnalysis.accesses[0].authorizationEvidence.effectiveRole,'UNKNOWN');
});
test('Route JSON destructuring and static aliases preserve input origins',()=>{
 const r=run("const body=await req.json();const {title:renamed,user_id}=body;const alias=renamed;return db.from('items').insert({title:alias,user_id});");
 assert.equal(field(r,'title'),'REQUEST_CONTROLLED');assert.equal(field(r,'user_id'),'REQUEST_CONTROLLED');
 assert.ok(write(r).dataFields.every(f=>f.sourceLocations.length>0));
});
test('verified API ID plus absence exit is evidence, not runtime authentication',()=>{
 for(const [method,item,key] of [['getUser','user','id'],['getClaims','claims','sub']]){
  const r=run(`const {data:{${item}}}=await db.auth.${method}();if(!${item})throw new Error('missing');const identity=${item}.${key};return db.from('items').update({user_id:identity}).match({user_id:identity});`,{policy:'auth.uid()=user_id'});
  assert.equal(field(r,'user_id'),'VERIFIED_USER_EVIDENCE');assert.equal(write(r).filters[0].source,'VERIFIED_USER_EVIDENCE');
  assert.equal(r.supabaseAnalysis.accesses[0].authorizationEvidence.effectiveRole,'UNKNOWN');
 }
});
test('session, ignored auth result, misleading names and unknown helpers do not become verified identities',()=>{
 const r=run("const {data:{session}}=await db.auth.getSession();const authenticatedUser=externalAuth();return db.from('items').insert({user_id:session.user.id,other:authenticatedUser.id});");
 assert.equal(field(r,'user_id'),'SESSION_UNVERIFIED');assert.equal(field(r,'other'),'UNKNOWN');
 const x=run("const {data:{user}}=await db.auth.getUser();return db.from('items').insert({user_id:user.id});");
 assert.equal(field(x,'user_id'),'UNKNOWN');
});
test('DELETE has no write payload; filters are independent request evidence',()=>{
 const r=run("const form=await req.formData();return db.from('items').delete().eq('id',form.get('id'));");
 assert.equal(write(r).dataStatus,'NO_PAYLOAD');assert.deepEqual(write(r).dataFields,[]);assert.equal(write(r).filters[0].source,'REQUEST_CONTROLLED');
});
test('spread, computed fields, duplicate fields and unsupported transformations are unknown',()=>{
 for(const object of ['{...body}','{[body.key]:body.value}',"{title:'fixed',title:body.title}"]){
  const r=run(`const body=await req.json();return db.from('items').insert(${object});`);
  assert.equal(write(r).dataStatus,'UNKNOWN');assert.deepEqual(write(r).dataFields,[]);
 }
 assert.equal(field(run("const body=await req.json();return db.from('items').insert({title:transform(body.title)});"),'title'),'UNKNOWN');
});
test('mutations, escapes and lexical shadows cannot retain an origin proof',()=>{
 for(const pre of ["let body=await req.json();body=other;", "const body=await req.json();external(body);", "const body=await req.json();body.title++;", "const body=await req.json();delete body.title;"]){
  assert.equal(field(run(pre+"return db.from('items').insert({title:body.title});"),'title'),'UNKNOWN');
 }
 assert.equal(field(run("const String=custom;return db.from('items').insert({title:String(form.get('title'))});",{action:true}),'title'),'UNKNOWN');
});
test('helper declarations and unknown clients do not gain request-write evidence',()=>{
 const a=run("return db.from('items').insert({title:'fixed'});");assert.ok(write(a));
 const helper=analyze({files:[{filePath:'lib/helper.ts',content:head+"export async function save(input){return db.from('items').insert({title:input.title});}"}],nodeManifests:[{filePath:'package.json',next:'15.2.0'}]});
 assert.ok(!helper.supabaseAnalysis.accesses[0].writeEvidence);
 const unknown=run("return external.from('items').insert({title:await req.text()});");assert.ok(!write(unknown));
});
test('field limits preserve UNKNOWN and output never includes literal values',()=>{
 const r=run("return db.from('items').insert({"+Array.from({length:18},(_,i)=>`field${i}:'private-placeholder'`).join(',')+"});");
 assert.equal(write(r).dataStatus,'UNKNOWN');assert.ok(write(r).limitations.includes('WRITE_FIELDS_LIMIT'));
 assert.ok(!JSON.stringify(write(r)).includes('private-placeholder'));
});
