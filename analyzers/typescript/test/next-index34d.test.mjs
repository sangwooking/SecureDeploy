import {test} from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';
import {syntaxIndex,indexSyntax} from '../syntax-index.mjs';
import {analyze} from '../analyzer.mjs';

test('cached Next syntax facts match the original full-walk binding and write definitions',()=>{
 const ast=ts.createSourceFile('app/api/task/route.ts',`import {process as other, named} from 'x';
 const x=1;function outer(arg){let local=arg;function nested(){'use strict';'use server';return local;}local=2;}
 export async function GET(request){process.env.KEY='changed';return request;}`,ts.ScriptTarget.Latest,true);
 const index=syntaxIndex(),bindings=new Set(),writes=new Set();
 const walk=n=>{
  indexSyntax(ts,n,index);
  if(n.name&&ts.isIdentifier(n.name)&&(ts.isParameter(n)||ts.isVariableDeclaration(n)||ts.isFunctionDeclaration(n)
    ||ts.isClassDeclaration(n)||ts.isImportClause(n)||ts.isImportSpecifier(n)||ts.isNamespaceImport(n)||ts.isImportEqualsDeclaration(n)||ts.isBindingElement(n)))bindings.add(n.name.text);
  if(ts.isBinaryExpression(n)&&ts.isAssignmentOperator(n.operatorToken.kind)){
   let base=n.left;while(ts.isPropertyAccessExpression(base)||ts.isElementAccessExpression(base))base=base.expression;
   if(ts.isIdentifier(base))writes.add(base.text);
  }
  ts.forEachChild(n,walk);
 };walk(ast);
 assert.deepEqual([...(index.nextBindings??index.bindings)].sort(),[...bindings].sort());
 assert.deepEqual([...index.writes].sort(),[...writes].sort());
 assert.equal(index.nextInlineServerClosure,true);
});
test('large uncalled syntax does not consume Next request flow steps twice',()=>{
 const input={nodeManifests:[{filePath:'package.json',next:'15.2.4'}],files:[{filePath:'app/api/task/route.ts',content:
  `function uncalled(){${Array.from({length:1800},(_,i)=>'let n'+i+'=0;').join('')}}export async function GET(request){return fetch(new URL(request.url).searchParams.get('url'));}`}]};
 const result=analyze(input,{maxSteps:5000});
 assert.equal(result.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH').length,1);
 assert.ok(result.supabaseAnalysis.budgetUsage.STEPS_ENTRY_DISCOVERY<500);
 assert.equal(analyze(input,{maxNodes:30}).findings.length,0);
 assert.equal(analyze(input,{maxSteps:10}).findings.length,0);
});
