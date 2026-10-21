import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const run=(content,extra=[],filePath='app/api/check/route.ts',version='15.3.0')=>analyze({
  files:[{filePath,content},...extra],nodeManifests:[{filePath:'package.json',next:version}]
});
const leaks=r=>r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');
const ssrf=r=>r.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW');

test('Next route request query reaches fetch through a relative helper',()=>{
  const r=run(`import {send} from '../../../lib/send'; export async function GET(req: Request){
    return send(new URL(req.url).searchParams.get('destination')); }`,[
    {filePath:'lib/send.ts',content:`export async function send(url:string){await fetch(url); return Response.json({ok:true});}`}]);
  assert.equal(ssrf(r).length,1);
  assert.equal(ssrf(r)[0].sink.filePath,'lib/send.ts');
  assert.equal(r.authorizationContexts[0].entry.kind,'NEXT_ROUTE_HANDLER');
});
test('Next fixed destination query data is not destination control',()=>{
  assert.equal(ssrf(run(`export async function POST(req:Request){const data=await req.json();
    await fetch('https://service.example/search?q='+encodeURIComponent(data.query));return Response.json({ok:true});}`)).length,0);
});
test('private environment response and internal use are distinguished',()=>{
  const r=run(`import {NextResponse as Reply} from 'next/server';export async function GET(){
    return Reply.json({value:process.env.SERVICE_SECRET});}`);
  assert.equal(leaks(r).length,1);
  assert.equal(leaks(r)[0].disposition,'REVIEW_REQUIRED');
  assert.equal(leaks(run(`export async function GET(){await useKey(process.env.SERVICE_SECRET);return Response.json({ok:true});}`)).length,0);
  assert.equal(leaks(run(`export async function GET(){return Response.json({url:process.env.NEXT_PUBLIC_SITE_URL});}`)).length,0);
  assert.equal(leaks(run(`export async function GET(){return Response.json({value:mask(process.env.SERVICE_SECRET)});}`)).length,0);
});
test('server function arguments and serializable returns use separate declared boundary',()=>{
  const r=run(`'use server';export async function inspect(input:FormData){await fetch(input.get('url'));return {value:process.env.PRIVATE_KEY};}`,[],'app/actions.ts');
  assert.equal(ssrf(r).length,1);assert.equal(leaks(r).length,1);
  assert.equal(r.authorizationContexts[0].entry.kind,'NEXT_SERVER_FUNCTION');
  assert.ok(r.files[0].limitations.includes('NEXT_SERVER_FUNCTION_INVOCATION_NOT_VERIFIED'));
});
test('route params await, formData and headers are input sources',()=>{
  for(const source of [`(await context.params).url`,`(await req.formData()).get('url')`,`req.headers.get('x-target')`,`req.nextUrl.searchParams.get('url')`]) {
    const r=run(`export async function PATCH(req:Request,context:any){await fetch(${source});return Response.json({ok:true});}`,[],'app/api/[url]/route.ts');
    assert.equal(ssrf(r).length,1,source);
  }
});
test('static route and nonexistent dynamic params are not invented request input',()=>{
  for(const file of ['app/api/fixed/route.ts','app/api/[id]/route.ts'])
    assert.equal(ssrf(run(`export async function GET(req:Request,ctx:any){return fetch((await ctx.params).url);}`,[],file)).length,0);
});
test('client, arbitrary paths, unsupported versions and missing manifest do not become routes',()=>{
  assert.equal(run(`'use client';export async function GET(req:Request){return fetch(req.url);}`).authorizationContexts.length,0);
  assert.equal(run(`export async function GET(req:Request){return fetch(req.url);}`,[],'tools/route.ts').authorizationContexts.length,0);
  assert.equal(run(`export async function GET(req:Request){return fetch(req.url);}`,[],'app/api/route.ts','12.2.0').authorizationContexts.length,0);
  assert.equal(analyze({files:[{filePath:'app/api/route.ts',content:'export async function GET(){}'}]}).authorizationContexts.length,0);
});
test('inline server closure and Pages API remain explicitly unverified',()=>{
  const r=run(`export default function Page(){async function save(data:FormData){'use server';return process.env.PRIVATE_KEY;}return null;}`,[],'app/page.tsx');
  assert.equal(leaks(r).length,0);assert.ok(r.files[0].limitations.includes('NEXT_INLINE_SERVER_CLOSURE_NOT_SUPPORTED'));
  const pages=run(`export default function handler(req,res){res.json({ok:true});}`,[],'pages/api/check.ts');
  assert.ok(pages.files[0].limitations.includes('NEXT_PAGES_API_NOT_SUPPORTED'));
});
test('type-only response import and shadowed process are not trusted builtins',()=>{
  assert.equal(leaks(run(`import type {NextResponse} from 'next/server';export async function GET(){return NextResponse.json(process.env.PRIVATE_KEY);}`)).length,0);
  assert.equal(leaks(run(`export async function GET(process:any){return Response.json(process.env.PRIVATE_KEY);}`)).length,0);
});
test('src app JavaScript, function directive and local return preserve the same boundary',()=>{
  const r=run(`import {reply} from '../../../lib/reply';export async function DELETE(req){return reply(process.env.API_KEY);}`,
    [{filePath:'src/lib/reply.js',content:`export function reply(value){return Response.json({value});}`}],'src/app/api/check/route.js');
  assert.equal(leaks(r).length,1);assert.equal(leaks(r)[0].sink.filePath,'src/lib/reply.js');
  const f=run(`export async function inspect(arg){'use server';await fetch(arg);return {ok:true};}`,[],'lib/actions.js');
  assert.equal(ssrf(f).length,1);
});
test('authentication reference and server-only are not resource permission or safety proofs',()=>{
  const r=run(`import 'server-only';export async function GET(){const user=await auth();if(!user)return Response.json({error:true});return Response.json({value:process.env.API_KEY});}`);
  assert.equal(r.authorizationContexts[0].conclusion,'NOT_VERIFIED');
  assert.ok(r.files[0].limitations.includes('NEXT_SERVER_ONLY_DECLARATION_NOT_RUNTIME_PROOF'));
});
test('parse, discovery and function budgets remain partial, never safe',()=>{
  const filePath='app/api/check/route.ts';
  const input={files:[{filePath,content:`export async function GET(req){return fetch(req.url);}`}],nodeManifests:[{filePath:'package.json',next:'16.0.0'}]};
  for(const overrides of [{maxSteps:1},{maxNodes:1},{maxFileChars:1}]) {
    const r=analyze(input,overrides);assert.equal(r.status,'PARTIAL');assert.equal(r.findings.length,0);
  }
  assert.equal(run('export async function GET( {').files[0].parseStatus,'PARSE_FAILED');
});
