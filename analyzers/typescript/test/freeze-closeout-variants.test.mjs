import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyzePolicies} from '../rls.mjs';
import {classify} from '../url-context.mjs';

// Additional same-curator regression variants, not independent holdout accuracy.
const base='CREATE TABLE public.records(id uuid,subject uuid);ALTER TABLE public.records ENABLE ROW LEVEL SECURITY;GRANT UPDATE ON public.records TO authenticated;';
const broad='CREATE POLICY access ON public.records FOR UPDATE TO authenticated USING(true) WITH CHECK(true);';
const owner='ALTER POLICY access ON public.records USING(subject=auth.uid()) WITH CHECK(subject=auth.uid());';
const file=(name,content,status='SELECTED')=>({filePath:'supabase/migrations/'+name,content,status});
const cases=[
  ['RISK',[file('100_create.sql',base+broad)],'ALLOW',true],
  ['NORMAL',[file('10_create.sql',base+broad),file('2_guard.sql',owner)],'UID_COLUMN_EQUALITY',false],
  ['NORMAL',[file('002_create.sql',base+broad),file('010_drop.sql','DROP POLICY access ON public.records;')],'DENY',false],
  ['NORMAL',[file('001_create.sql',base+broad),file('002_revoke.sql','REVOKE UPDATE ON public.records FROM authenticated;')],'ALLOW',false],
  ['UNKNOWN',[file('001_create.sql',base+broad),file('latest.sql',owner)],'UNKNOWN',false],
  ['UNKNOWN',[file('001_a.sql',base+broad),file('001_b.sql',owner)],'UNKNOWN',false],
  ['UNKNOWN',[file('001_create.sql',base+broad),file('002_omitted.sql','', 'EXCLUDED')],'UNKNOWN',false],
  ['UNKNOWN',[file('001_create.sql',base+broad),file('002_dynamic.sql','DO $$ BEGIN NULL; END $$;')],'UNKNOWN',false],
];
test('migration variants retain risky declarations, actual final defenses, and explicit abstention',()=>{
  for(const [label,input,state,candidate] of cases){
    for(const files of [input,[...input].reverse()]){
      const r=analyzePolicies(files,()=>{});
      const op=r.tables[0].operations.find(o=>o.role==='authenticated'&&o.operation==='UPDATE');
      assert.equal(op.state,state,label);assert.equal(op.candidate,candidate,label);
      if(label==='UNKNOWN')assert.ok(r.tables[0].limitations.some(x=>x.startsWith('MIGRATION_')));
    }
  }
});
test('fixed anchor variations never expand into a general sanitizer or dynamic HTML proof',()=>{
  const values=[
    ['NORMAL','<div><a href="https://reference.example.invalid/guide#section">Reference</a></div>'],
    ['RISK','<a href="https://reference.example.invalid" onpointerenter="act()">Reference</a>'],
    ['RISK','<a href="data:text/html,active">Reference</a>'],
    ['UNKNOWN','<a HREF="https://reference.example.invalid">Reference</a>'],
    ['UNKNOWN','<a href="https://reference.example.invalid" download>Reference</a>'],
  ];
  for(const [label,html] of values){
    const source=`const Page=()=> <section dangerouslySetInnerHTML={{__html:${JSON.stringify(html)}}}/>;`;
    const row=classify([{filePath:'ui/Reference.tsx',content:source}]).files[0];
    assert.equal(row.excludedHtmlLines.length,label==='NORMAL'?1:0,label);
  }
});
