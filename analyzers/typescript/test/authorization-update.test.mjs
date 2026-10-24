import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const owner='auth.uid()=user_id';
const evaluate=(using,check,{grant=true,extra=''}={})=>{
 const sql='CREATE TABLE public.records(user_id uuid);ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;'+
  (grant?'GRANT SELECT,UPDATE ON public.records TO authenticated;':'')+
  'CREATE POLICY reading ON public.records FOR SELECT TO authenticated USING(true);'+
  `CREATE POLICY updating ON public.records FOR UPDATE TO authenticated USING(${using})`+(check===null?'':` WITH CHECK(${check})`)+';'+extra;
 const r=analyze({files:[{filePath:'app/api/records/route.ts',content:"import {createClient} from '@supabase/supabase-js';const db=createClient('url',process.env.ANON_KEY);export async function POST(){return db.from('records').update({});}"}],nodeManifests:[{filePath:'package.json',next:'15.2.0'}],policyFiles:[{filePath:'supabase/migrations/20260101000000_records.sql',status:'SELECTED',content:sql}]}).supabaseAnalysis;
 return {snapshot:r,op:r.tables[0].operations.find(o=>o.role==='authenticated'&&o.operation==='UPDATE'),access:r.accesses[0].authorizationEvidence};
};
test('UPDATE existing and replacement row conditions cannot substitute for each other',()=>{
 for(const [using,check,state]of [[owner,'true','UPDATE_NEW_ROW_UNRESTRICTED'],['true',owner,'UPDATE_EXISTING_ROWS_UNRESTRICTED']]){
  const {snapshot,op,access}=evaluate(using,check);
  assert.equal(op.state,state);assert.equal(op.candidate,true);assert.equal(access.state,'BROAD_ACCESS_REVIEW');
  assert.equal(snapshot.findings.length,1);assert.equal(snapshot.findings[0].priority,'REVIEW_REQUIRED');
  assert.equal(snapshot.findings[0].comparisonPolicy,'NOT_COMPARED');
 }
});
test('omitted WITH CHECK inherits USING, unlike explicit true',()=>{
 for(const check of [null,owner]){
  const {snapshot,op,access}=evaluate(owner,check);assert.equal(op.state,'UID_COLUMN_EQUALITY');
  assert.equal(snapshot.findings.length,0);assert.equal(access.state,'CONFIRMED_POLICY_EVIDENCE');
 }
});
test('denial, unknown clauses, missing grants and different owner columns never become partial-open candidates',()=>{
 for(const [using,check,options]of [[owner,'false',{}],['false',owner,{}],[owner,'external_check(user_id)',{}],['external_check(user_id)',owner,{}],['true',owner,{grant:false}],[owner,'auth.uid()=reviewer_id',{}]]){
  const {snapshot,op}=evaluate(using,check,options);assert.equal(op.candidate,false);assert.equal(snapshot.findings.length,0);
 }
});
test('restrictive ownership constraints close both UPDATE phases despite a broad permissive policy',()=>{
 const {snapshot,op}=evaluate('true','true',{extra:`CREATE POLICY guard ON public.records AS RESTRICTIVE FOR UPDATE TO authenticated USING(${owner});`});
 assert.equal(op.state,'UID_COLUMN_EQUALITY');assert.equal(snapshot.findings.length,0);
});
