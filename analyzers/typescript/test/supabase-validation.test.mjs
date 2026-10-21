import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import ts from 'typescript';
import {supabaseAnalysis} from '../supabase.mjs';
// Separately authored variants, same curator. Not a blind or external accuracy study.
const base='CREATE TABLE public.documents(id uuid,creator uuid);GRANT UPDATE,DELETE ON public.documents TO authenticated;';
const cases=[
 ['RISK','ALTER TABLE public.documents DISABLE ROW LEVEL SECURITY;'],
 ['RISK','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY sharing ON public.documents FOR ALL TO authenticated USING(true);'],
 ['RISK','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY signed_in ON public.documents TO authenticated USING((SELECT auth.uid()) IS NOT NULL);'],
 ['RISK','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY shared ON public.documents USING(true);CREATE POLICY extra ON public.documents AS RESTRICTIVE USING(true);'],
 ['NORMAL','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY limited ON public.documents TO authenticated USING(creator=auth.uid());'],
 ['NORMAL','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY public_read ON public.documents FOR SELECT TO public USING(true);'],
 ['NORMAL','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY blocked ON public.documents USING(false);'],
 ['NORMAL','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY shared ON public.documents USING(true);CREATE POLICY limited ON public.documents AS RESTRICTIVE USING(creator=(SELECT auth.uid()));'],
 ['UNKNOWN','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY helper ON public.documents USING(can_edit(auth.uid(),id));'],
 ['UNKNOWN','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY environment_role ON public.documents TO current_user USING(true);'],
 ['UNKNOWN','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY literal ON public.documents USING("true");'],
 ['UNKNOWN','ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;DO $$BEGIN EXECUTE command;END$$;'],
];
test('held-separate validation variants distinguish four broad declarations, four protected and four unknown',()=>{
 const counts={RISK:0,NORMAL:0,UNKNOWN:0};
 for(const [expected,sql]of cases){const r=analyze({files:[],policyFiles:[{filePath:'supabase/migrations/20260401000000_ownership.sql',status:'SELECTED',content:base+sql}]}).supabaseAnalysis;
  assert.equal(r.findings.length,expected==='RISK'?1:0,sql);
  if(expected==='UNKNOWN')assert.ok(r.tables[0].operations.some(o=>o.role==='authenticated'&&o.state==='UNKNOWN'),sql);
  counts[expected]++;
 }
 assert.deepEqual(counts,{RISK:4,NORMAL:4,UNKNOWN:4});
});
test('ordering is deterministic and duplicate timestamps or schema snapshots are not merged as live truth',()=>{
 const make=(name,content)=>({filePath:'supabase/migrations/'+name,status:'SELECTED',content});
 const initial=make('20260101000000_first.sql',base+'ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;CREATE POLICY p ON public.documents USING(true);');
 const changed=make('20260102000000_changed.sql','ALTER POLICY p ON public.documents USING(auth.uid()=creator);');
 const run=policyFiles=>analyze({files:[],policyFiles}).supabaseAnalysis;
 assert.deepEqual(run([changed,initial]),run([initial,changed]));
 assert.equal(run([initial,{...changed,filePath:'supabase/migrations/20260101000000_duplicate.sql'}]).tables[0].rls,'UNKNOWN');
 assert.equal(run([initial,{filePath:'schema.sql',status:'SELECTED',content:base}]).tables.find(t=>t.scope==='').rls,'UNKNOWN');
 const limited=analyze({files:[],policyFiles:[initial]},{maxSteps:1}).supabaseAnalysis;
  assert.equal(limited.findings.length,0);assert.ok(limited.files.some(f=>['PARSE_FAILED','NOT_RUN','LIMIT_EXCEEDED'].includes(f.status)));
});
test('a later Client budget failure does not erase already completed SQL declaration evidence',()=>{
 const ast=ts.createSourceFile('large.ts','const x={'+Array.from({length:400},(_,i)=>`v${i}:${i}`).join(',')+'};',ts.ScriptTarget.Latest,true);
 const mod={filePath:'large.ts',ast,imports:new Map(),hasSupabaseSyntax:true};let steps=0;
 const r=supabaseAnalysis({ts,modules:new Map([['large.ts',mod]]),input:{policyFiles:[{filePath:'supabase/migrations/20260101000000_sql.sql',status:'SELECTED',content:base}]},tick:()=>{if(++steps>300)throw Error('SUPABASE_BUDGET');}});
 assert.equal(r.tables.length,1);assert.equal(r.findings.length,1);assert.ok(r.limitations.includes('CLIENT_AST_BUDGET_LIMIT'));
 assert.equal(r.accesses.length,0);
});
