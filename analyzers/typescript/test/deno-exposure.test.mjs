import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const filePath='supabase/functions/example/index.ts';
const run=(body, prefix='', registration='Deno.serve', more=[])=>analyze({files:[{filePath,content:`${prefix}\n${registration}(async (req)=>{${body}});`},...more]});
const exposures=r=>r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');
const entered=r=>assert.equal(r.files[0].entrypoints,1);

test('Deno request-selected environment value reaches returned JSON with no environment names in metadata',()=>{
  const r=run('const name=new URL(req.url).searchParams.get("name");const value=Deno.env.get(name);return Response.json({value});');
  entered(r);assert.equal(exposures(r).length,1);
  assert.ok(exposures(r)[0].flow.some(l=>l.kind==='QUERY_PARAMETER'));
  assert.ok(exposures(r)[0].flow.some(l=>l.kind==='REQUEST_SELECTED_ENVIRONMENT_VALUE'));
  assert.ok(!JSON.stringify(r).includes('SUPABASE_SERVICE_ROLE_KEY'));
});
test('verified standard serve import and local function arguments preserve environment-response evidence',()=>{
  const r=run('return reply(Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));',
    'import {serve as start} from "https://deno.land/std@0.168.0/http/server.ts";import {reply} from "../../../reply.ts";', 'start',
    [{filePath:'reply.ts',content:'export function reply(value){return new Response(JSON.stringify({value}));}'}]);
  entered(r);assert.equal(exposures(r).length,1);assert.ok(!JSON.stringify(r).includes('SUPABASE_SERVICE_ROLE_KEY'));
});
test('secret used only in server fetch headers is not a response leak',()=>{
  const r=run('const key=Deno.env.get("API_SECRET");await fetch("https://provider.example/api",{headers:{Authorization:key}});return Response.json({ok:true});');
  entered(r);assert.equal(exposures(r).length,0);
});
test('boolean existence and explicitly public configuration do not become secret leaks',()=>{
  for(const body of ['return Response.json({configured:!!Deno.env.get("API_SECRET")});',
    'return Response.json({key:Deno.env.get("SUPABASE_ANON_KEY")});',
    'return Response.json({key:Deno.env.get("SUPABASE_PUBLISHABLE_KEY")});',
    'return Response.json({url:Deno.env.get("PUBLIC_SITE_URL")});']){
    const r=run(body);entered(r);assert.equal(exposures(r).length,0);
  }
});
test('constructed but unreturned response, overwrite and false branch do not leak',()=>{
  for(const body of ['Response.json(Deno.env.get("API_SECRET"));return Response.json("ok");',
    'let x=Deno.env.get("API_SECRET");x="public";return Response.json(x);',
    'if(false)return Response.json(Deno.env.get("API_SECRET"));return Response.json("ok");']){
    const r=run(body);entered(r);assert.equal(exposures(r).length,0);
  }
});
test('unknown masking and unknown environment name without request provenance stay uncertain',()=>{
  for(const body of ['return Response.json(mask(Deno.env.get("API_SECRET")));',
    'return Response.json(Deno.env.get(externalName()));']){
    const r=run(body);entered(r);assert.equal(exposures(r).length,0);
    assert.ok(r.exposureUses.some(u=>['FLOW_UNRESOLVED','SENSITIVITY_UNVERIFIED'].includes(u.status)));
  }
});
test('a generic serve function and shadowed Deno do not establish runtime provenance',()=>{
  for(const [prefix,registration] of [['function serve(handler){}','serve'],
    ['const Deno=customRuntime();','Deno.serve'],
    ['import {serve} from "./custom.ts";','serve']]){
    const r=run('return Response.json(Deno.env.get("API_SECRET"));',prefix,registration);
    assert.equal(r.files[0].entrypoints,0);assert.equal(exposures(r).length,0);
  }
});
test('computed response key and exception alternatives retain only the returned environment path',()=>{
  const r=run('try{const {name}=await req.json();if(!name)throw new Error("name required");const x=Deno.env.get(name);return new Response(JSON.stringify({[name]:x}));}catch(e){return Response.json({error:"request failed"});}');
  entered(r);assert.equal(exposures(r).length,1);
  assert.ok(exposures(r)[0].limitations.includes('AUTHORIZATION_AND_DEPLOYMENT_NOT_VERIFIED'));
});
test('unknown wrappers, response arrays and non-JSON object bodies are not returned-body proof',()=>{
  for(const body of ['return wrap(Response.json(Deno.env.get("API_SECRET")));',
    'return [Response.json(Deno.env.get("API_SECRET"))];',
    'return new Response({value:Deno.env.get("API_SECRET")});',
    'return Response.json({response:Response.json(Deno.env.get("API_SECRET"))});',
    'return Response.json([Response.json(Deno.env.get("API_SECRET"))]);',
    'return new Response(JSON.stringify(Response.json(Deno.env.get("API_SECRET"))));']){
    const r=run(body);entered(r);assert.equal(exposures(r).length,0,body);
  }
});
test('conditional response expressions keep per-response provenance instead of joining a safe sink to a secret source',()=>{
  const r=run('return req.method==="GET" ? Response.json(Deno.env.get("API_SECRET")) : Response.json("ok");');
  assert.equal(exposures(r).length,1);
});
