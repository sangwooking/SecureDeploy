// Authored static contracts; not new independent applications or runtime secrets.
export function secretInput(body,framework='next'){
 const content=framework==='deno'?`Deno.serve(async(req)=>{${body}});`:framework==='express'
  ?`const app=require('express')();app.get('/',async(req,res)=>{${body}});`
  :`import {NextResponse} from 'next/server';export async function GET(req){${body}}`;
 return {files:[{filePath:framework==='deno'?'supabase/functions/check/index.ts':framework==='express'?'server.cjs':'app/api/check/route.ts',content}],
  nodeManifests:framework==='express'?[{filePath:'package.json',express:'4.18.0'}]:framework==='next'?[{filePath:'package.json',next:'15.3.0'}]:[]};
}
export const secretCases=[];
for(const framework of ['next','deno','express']){
 const env=key=>framework==='deno'?`Deno.env.get(${JSON.stringify(key)})`:`process.env.${key}`;
 const secret=env('API_SECRET'),send=v=>framework==='express'?`res.json(${v});return;`:`return Response.json(${v});`;
 const cases=[
  ['direct','RISK',send(`{value:${secret}}`)],
  ['alias','RISK',`const value=${secret};const output={value};`+send('output')],
  ['property-write','RISK',`const output={status:'ok'};output.value=${secret};`+send('output')],
  ['object-alias-write','RISK',`const output={status:'ok'};const alias=output;alias.value=${secret};`+send('output')],
  ['nested-write','RISK',`const output={inner:{status:'ok'}};output.inner.value=${secret};`+send('output')],
  ['spread','RISK',`const internal={value:${secret}};const output={status:'ok',...internal};`+send('output')],
  ['nested','RISK',send(`{config:{value:${secret}}}`)],
  ['serialize','RISK',`const output={status:'ok'};output.value=${secret};`+(framework==='express'?"res.send(JSON.stringify(output));return;":"return new Response(JSON.stringify(output));")],
  ['spread-last-wins','RISK',`const output={value:'public',...{value:${secret}}};`+send('output')],
  ['query-selected-key','RISK',`const name=new URL(req.url).searchParams.get('name');const value=${framework==='deno'?'Deno.env.get(name)':'process.env[name]'};`+send('{value}')],
  ['public-anon','NORMAL',send(`{key:${env('SUPABASE_ANON_KEY')}}`)],
  ['public-publishable','NORMAL',send(`{key:${env('SUPABASE_PUBLISHABLE_KEY')}}`)],
  ['public-project-url','NORMAL',send(`{url:${env('SUPABASE_URL')}}`)],
  ['select-public-field','NORMAL',`const config={publicUrl:'https://example.invalid',value:${secret}};`+send('{publicUrl:config.publicUrl}')],
  ['overwrite','NORMAL',`const output={value:${secret},status:'ok'};output.value='public';`+send('output')],
  ['delete','NORMAL',`const output={value:${secret},status:'ok'};delete output.value;`+send('output')],
  ['alias-delete','NORMAL',`const output={value:${secret},status:'ok'};const alias=output;delete alias.value;`+send('output')],
  ['spread-safe-last','NORMAL',`const internal={value:${secret}};const output={...internal,value:'public',status:'ok'};`+send('output')],
  ['server-only','NORMAL',`const config={value:${secret}};`+send("{status:'ok'}")],
  ['copy-is-shallow','RISK',`const original={inner:{value:'public'}};const output={...original};original.inner.value=${secret};`+send('output')],
  ['root-copy-is-separate','NORMAL',`const original={value:'public'};const output={...original};original.value=${secret};`+send('output')],
  ['dynamic-write','UNKNOWN',`const output={status:'ok'};output[externalKey()]=${secret};`+send('output')],
  ['dynamic-delete','UNKNOWN',`const output={value:${secret}};delete output[externalKey()];`+send('output')],
  ['conditional-write','UNKNOWN',`const output={status:'ok'};if(req.url)output.value=${secret};`+send('output')],
  ['unknown-spread','UNKNOWN',`const output={...externalConfig(),value:${secret}};`+send('output')],
  ['unknown-transform','UNKNOWN',send(`mask(${secret})`)],
  ['unknown-sensitivity','UNKNOWN',send(`{value:${env('CUSTOM_SETTING')}}`)],
  ['json-hook','UNKNOWN',`const output={value:${secret},toJSON(){return {status:'ok'};}};`+send('output')],
  ['prototype-data','UNKNOWN',`const output={__proto__:{value:${secret}},status:'ok'};`+send('output')],
  ['escaped-object','UNKNOWN',`const output={value:${secret}};mutate(output);`+send('output')],
 ];
 for(const [id,truth,body]of cases)secretCases.push({id:framework+'-'+id,framework,truth,input:secretInput(body,framework)});
}
