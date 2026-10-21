import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

// Separately authored after implementation; same curator, not a blind/external study.
const cases=[
 ['RISK','const key=req.headers.get("X-Config");return Response.json(Deno.env.get(key));'],
 ['RISK','const name=await req.text();const a=Deno.env.get(name);const b=a;return new Response(b);'],
 ['RISK','return Response.json([Deno.env.get("PRIVATE_KEY")]);'],
 ['RISK','const x=Deno.env.get("ACCESS_TOKEN");if(req.method==="GET")return Response.json({x});return new Response("no");'],
 ['NORMAL','const k=Deno.env.get("API_KEY");return Response.json(k!==undefined);'],
 ['NORMAL','let x=Deno.env.get("API_SECRET");x=null;return Response.json(x);'],
 ['NORMAL','const x=Deno.env.get("SUPABASE_URL");return Response.json({x});'],
 ['NORMAL','return Response.json({build:"synthetic-release"});'],
 ['UNKNOWN','const x=Deno.env.get("API_KEY");return Response.json(externalTransform(x));'],
 ['UNKNOWN','return Response.json(Deno.env.get(await discoverName()));'],
 ['UNKNOWN','const x=Deno.env.get("API_KEY");return new Response(JSON.stringify({x},replacer));'],
 ['UNKNOWN','return opaqueWrapper(Response.json(Deno.env.get("API_KEY")));'],
];
test('validation matrix distinguishes four raw environment paths, four normal and four uncertain paths',()=>{
 const counts={RISK:0,NORMAL:0,UNKNOWN:0};
 for(const [expected,body]of cases){
   const r=analyze({files:[{filePath:'edge/service.ts',content:`Deno.serve({port:9000},async(req)=>{${body}});`}]});
   assert.equal(r.files[0].entrypoints,1);
   assert.equal(r.findings.some(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE'),expected==='RISK',body);
   if(expected==='UNKNOWN')assert.ok(r.files[0].limitations.length||r.exposureUses.some(u=>u.status==='FLOW_UNRESOLVED'));
   counts[expected]++;
 }
 assert.deepEqual(counts,{RISK:4,NORMAL:4,UNKNOWN:4});
});
test('registration origin and budgets survive file, function and parameter renaming',()=>{
 const files=[{filePath:'edge/entry.ts',content:'import {handler as callback} from "./reply";Deno.serve(callback);'},
  {filePath:'edge/reply.ts',content:'export function handler(incoming){return Response.json(Deno.env.get("API_KEY"));}'}];
 const r=analyze({files});assert.equal(r.findings.length,1);
 const limited=analyze({files},{maxSteps:1});assert.ok(limited.files.some(f=>f.parseStatus!=='PARSED'||f.limitations.length));
 assert.equal(limited.findings.length,0);
});
