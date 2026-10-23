// Grade B static contracts, authored before the v17 change; not external/blind validation.
import {createHash} from 'node:crypto';
export const prebetaBaseline=Object.freeze({commit:'cda9dfce238fe71361657885fe6380edf12c5fe5',engine:'ts-server-v16',
  counts:{TP:0,FP:0,FN:8,TN:7,UNKNOWN:5},interpretation:'FIXED_TARGET_MISSES_NOT_WITHIN_SUPPORTED_SCOPE_RECALL'});
const deno=body=>({files:[{filePath:'supabase/functions/check/index.ts',content:`Deno.serve(async request=>{${body}});`} ]});
const next=body=>({nodeManifests:[{filePath:'package.json',next:'14.2.0'}],files:[{filePath:'app/api/check/route.ts',content:`export async function GET(request){${body}}`} ]});
const express=(body,extra='')=>({nodeManifests:[{filePath:'package.json',express:'^4.18.0'}],files:[{filePath:'server.cjs',content:`const express=require('express');const app=express();${extra}app.get('/check',(request,response)=>{${body}});`} ]});
const fake='ghp_'+'b'.repeat(36);
export const prebetaCases=[
  {id:'deno-private-log',set:'REGRESSION',truth:'RISK',input:deno("console.log(Deno.env.get('API_SECRET'));return Response.json({ok:true});")},
  {id:'deno-selected-log',set:'REGRESSION',truth:'RISK',input:deno("const key=new URL(request.url).searchParams.get('key');console.warn(Deno.env.get(key));return new Response('ok');")},
  {id:'next-private-log',set:'REGRESSION',truth:'RISK',input:next("console.error(process.env.API_SECRET);return Response.json({ok:true});")},
  {id:'express-private-json',set:'REGRESSION',truth:'RISK',input:express("response.json({value:process.env.API_SECRET});")},
  {id:'express-literal-send',set:'REGRESSION',truth:'RISK',input:express(`response.send(${JSON.stringify(fake)});`)},
  {id:'deno-public-log',set:'REGRESSION',truth:'NORMAL',input:deno("console.log(Deno.env.get('SUPABASE_PUBLISHABLE_KEY'));return Response.json({ok:true});")},
  {id:'next-public-log',set:'REGRESSION',truth:'NORMAL',input:next("console.log(process.env.NEXT_PUBLIC_SITE_URL);return Response.json({ok:true});")},
  {id:'express-static-json',set:'REGRESSION',truth:'NORMAL',input:express("response.json({ok:true});")},
  {id:'express-overwritten',set:'REGRESSION',truth:'NORMAL',input:express("let value=process.env.API_SECRET;value='public';response.send(value);")},
  {id:'masked-log',set:'REGRESSION',truth:'UNKNOWN',input:deno("console.log(mask(Deno.env.get('API_SECRET')));return new Response('ok');")},
  {id:'express-opaque-response',set:'REGRESSION',truth:'UNKNOWN',input:express("response.json(mask(process.env.API_SECRET));")},
  {id:'express-mutated-response',set:'REGRESSION',truth:'UNKNOWN',input:express("response.json=custom;response.json(process.env.API_SECRET);")},
  {id:'validation-structured-log',set:'VALIDATION',truth:'RISK',input:deno("const record={ready:true,credential:Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')};console.info(JSON.stringify(record));return new Response('ok');")},
  {id:'validation-module-response',set:'VALIDATION',truth:'RISK',input:{nodeManifests:[{filePath:'package.json',express:'^4.18.0'}],files:[
    {filePath:'main.mjs',content:"import express from 'express';import {report} from './handler.mjs';const app=express();const router=express.Router();router.get('/report',report);app.use('/api',router);"},
    {filePath:'handler.mjs',content:"export function report(incoming,outgoing){const result={ready:true,value:process.env['API_SECRET']};return outgoing.status(202).json(result);}"}]}},
  {id:'validation-helper-end',set:'VALIDATION',truth:'RISK',input:express("reply(response,process.env.API_SECRET);","function reply(channel,value){channel.end(JSON.stringify({value}));}")},
  {id:'validation-public-node-key',set:'VALIDATION',truth:'NORMAL',input:express("response.json({key:process.env.SUPABASE_ANON_KEY});")},
  {id:'validation-internal-use',set:'VALIDATION',truth:'NORMAL',input:express("const value=process.env.API_SECRET;await fetch('https://service.example.invalid',{headers:{Authorization:value}});response.json({ready:true});")},
  {id:'validation-custom-channel',set:'VALIDATION',truth:'NORMAL',input:express(`const local={json:x=>x};local.json(${JSON.stringify(fake)});response.json({ready:true});`)},
  {id:'validation-unknown-helper',set:'VALIDATION',truth:'UNKNOWN',input:express("sendElsewhere(response,process.env.API_SECRET);")},
  {id:'validation-unknown-key',set:'VALIDATION',truth:'UNKNOWN',input:deno("console.log(Deno.env.get(chooseName()));return new Response('ok');")},
// Variations originally planned for validation were observed while fixing the implementation.
// Keep their provenance, but promote the entire observed set to development regression.
].map(c=>({...c,plannedSet:c.set,set:'REGRESSION'}));
export function summarizePrebeta(analyze){
  const counts={TP:0,FP:0,FN:0,TN:0,UNKNOWN:0};
  const cases=prebetaCases.map(c=>{const r=analyze(c.input);const found=r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');
    const verdict=c.truth==='UNKNOWN'?(found.length?'UNEXPECTED_CANDIDATE':'UNKNOWN'):c.truth==='RISK'?(found.length?'TP':'FN'):(found.length?'FP':'TN');counts[verdict]=(counts[verdict]??0)+1;
    return {id:c.id,set:c.set,truth:c.truth,verdict,inputHash:createHash('sha256').update(JSON.stringify(c.input)).digest('hex'),findings:found.length,uncertain:r.exposureUses.filter(u=>u.status==='FLOW_UNRESOLVED'||u.status==='SENSITIVITY_UNVERIFIED').length,
      parsed:r.files.filter(f=>f.parseStatus==='PARSED').length,entrypoints:r.files.reduce((a,f)=>a+f.entrypoints,0)};});
  return {grade:'B_SYNTHETIC',externalBlindReview:false,baseline:prebetaBaseline,counts,cases};
}
