// Separate post-implementation synthetic corpus. Not blinded; fixed after first evaluation.
import{encoding}from'./worker-v54-inputs.mjs';
const manifest={filePath:'package.json',moduleType:'module',resolutionStatus:'PARSED',express:'4.21.2',next:'15.3.0'};
const cases=[];function add(id,body,truth,reason,{path='/show/:slug',method='get'}={}){cases.push({id,truth,oracle:reason,input:{nodeManifests:[manifest],files:[{filePath:'new/site.mjs',content:`import express from 'express';const app=express();${encoding}app.${method}('${path}',(req,res)=>{${body}});`}]}});}
add('query-text','res.send(`<section><p>${req.query.message}</p></section>`);',true,'Query text interpolated into a supported HTML DATA slot.');
add('body-concatenation','res.type("html");res.end("<div>"+req.body.message+"</div>");',true,'Explicit HTML response and raw request body property.');
add('header-text','res.send(`<p>${req.headers["x-display"]}</p>`);',true,'A header field is reflected as HTML text.');
add('declared-param','res.send(`<p>${req.params.slug}</p>`);',true,'The route declares the exact parameter field.');
add('constant-prefix','const text="<main><h2>Known</h2><p>"+req.query.value+"</p></main>";res.send(text);',true,'Known constant markup surrounding an unencoded input.');
add('encoded','res.send(`<p>${encode(req.query.value)}</p>`);',false,'Closed five-entity replacement protects HTML text.');
add('json','res.json({value:req.query.value});',false,'Normal JSON response, no forced HTML MIME.');
add('plain','res.type("text/plain").send(`<p>${req.query.value}</p>`);',false,'Text/plain response does not parse HTML.');
add('literal','res.send("<p>Known constant</p>");',false,'No user input.');
add('head-no-body','res.send(`<p>${req.query.value}</p>`);',false,'HEAD route does not return an HTTP response body.',{method:'head'});
add('status-no-body','res.status(204).send(`<p>${req.query.value}</p>`);',false,'204 response does not contain a body.');
add('attribute-supported-later','res.send(`<span title="${req.query.value}">x</span>`);',true,'Raw quoted attribute is unsafe in general, intentionally outside the first HTML text contract.');
add('quoted-greater-than','res.send(`<span title="prefix>${req.query.value}">x</span>`);',null,'Greater-than is inside an attribute, not an HTML text slot.');
for(const [id,prefix]of[['event','<a onclick="'],['url','<a href="'],['style','<b style="'],['nested-document','<iframe srcdoc="']])add(id,'res.send(`'+prefix+'${req.query.value}suffix`);',null,'Unsupported execution context requires review, not a text-flow Finding.');
add('opaque-cleaner','res.send(clean(req.query.value));',null,'Unknown cleaner may change input; no confirmed flow proof.');
add('conditional-validation','if(!allowed(req.query.value))return res.end();res.send(`<p>${req.query.value}</p>`);',null,'Unknown validation cannot be assumed absent or effective.');
add('missing-parameter','res.send(`<p>${req.params.absent}</p>`);',null,'No registration for this parameter; do not invent a Source.');
cases.push({id:'cross-file-alias-return',truth:true,oracle:'Static selected import, object alias and returned HTML text flow.',input:{nodeManifests:[manifest],files:[{filePath:'new/site.mjs',content:"import express from 'express';import {format} from './format.mjs';const app=express();app.get('/show',(req,res)=>{const o={text:req.query.message};res.send(format(o));});"},{filePath:'new/format.mjs',content:'export function format(item){const alias=item;return `<article>${alias.text}</article>`;}'}]}});
cases.push({id:'returned-native-response',truth:true,oracle:'Native Response is actually returned by a declared GET route with explicit text/html.',input:{nodeManifests:[manifest],files:[{filePath:'app/api/display/route.ts',content:'export function GET(request){const v=new URL(request.url).searchParams.get("msg");return new Response(v,{headers:{"content-type":"text/html"}});}'}]}});
cases.push({id:'unused-native-response',truth:false,oracle:'Tainted Response is constructed but never returned; actual response is JSON.',input:{nodeManifests:[manifest],files:[{filePath:'app/api/display/route.ts',content:'export function GET(request){const unused=new Response(new URL(request.url).searchParams.get("msg"),{headers:{"content-type":"text/html"}});return Response.json({ok:true});}'}]}});
export{cases};
