import {test} from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';
import {syntaxIndex,indexSyntax} from '../syntax-index.mjs';
import {supabaseAnalysis} from '../supabase.mjs';

test('bounded parse index preserves existing client semantics and source order',()=>{
  for(const tail of [
    "const a=createClient('https://example.invalid',process.env.ANON_KEY);a.from('notes').select();",
    "const a=createClient('https://example.invalid',process.env.ANON_KEY);const b=a;b.from('notes').update({});",
    "let a=createClient('https://example.invalid',process.env.ANON_KEY);a=custom();a.from('notes').delete();",
    "function read(createClient){return createClient('https://example.invalid','example').from('notes').select();}",
    "const a=customFactory();a.from('notes').select();"
  ]){
    const ast=ts.createSourceFile('client.ts',"import {createClient} from '@supabase/supabase-js';"+tail,ts.ScriptTarget.Latest,true);
    const mod={ast,filePath:'client.ts',hasSupabaseSyntax:true,imports:new Map([['createClient',{spec:'@supabase/supabase-js',exported:'createClient'}]])};
    const run=()=>supabaseAnalysis({ts,modules:new Map([['client.ts',mod]]),input:{},tick:()=>{}});
    const prior=run(),index=syntaxIndex(),stack=[ast];
    while(stack.length){const node=stack.pop();indexSyntax(ts,node,index);ts.forEachChild(node,n=>{stack.push(n);});}
    index.nodes.sort((a,b)=>a.pos-b.pos||b.end-a.end);mod.syntaxIndex=index;
    const legacy=r=>({...r,accesses:r.accesses.map(({authorizationEvidence,...a})=>a)});
    assert.deepEqual(legacy(run()),legacy(prior));
  }
});
