// Authored contracts, not a blind or externally approved security oracle.
export const xss25Cases=[];
const view=v=>`const View=()=> <div dangerouslySetInnerHTML={{__html:${v}}}/>;`;
for(const [id,truth,code]of [
 ['static','NORMAL',view("'<b>fixed</b>'")],
 ['choices','NORMAL',view("flag?'<b>A</b>':'<i>B</i>'")],
 ['alias','NORMAL',"const a='<p>A</p>';const b='<p>B</p>';const html=flag?a:b;"+view('html')],
 ['true','NORMAL',view("true?'<b>A</b>':'<img src=x onerror=run()>'")],
 ['false','NORMAL',view("false?'<img src=x onerror=run()>':'<b>A</b>'")],
 ['nested','NORMAL',view("a?(b?'<p>A</p>':'<p>B</p>'):'<p>C</p>'")],
 ['anchors','NORMAL',view(`flag?'<a href="https://a.example.invalid/">A</a>':'<a href="https://b.example.invalid/">B</a>'`)],
 ['jsx-text','NORMAL','function View(){return <p>{new URLSearchParams(location.search).get("text")}</p>}'],
 ['text-content','NORMAL','const box=document.createElement("div");box.textContent=location.hash;'],
 ['purified','NORMAL',"import DOMPurify from 'dompurify';const html=DOMPurify.sanitize(location.hash);"+view('html')],
 ['location','RISK',view("new URLSearchParams(location.search).get('html')")],
 ['alias-source','RISK',"const html=location.hash;"+view('html')],
 ['mixed','RISK',view("flag?'<b>fixed</b>':location.hash")],
 ['concat','RISK',view("'<b>'+location.hash+'</b>'")],
 ['after-sanitize','RISK',"import DOMPurify from 'dompurify';const html=DOMPurify.sanitize('fixed')+location.hash;"+view('html')],
 ['unknown-sanitizer','UNKNOWN',view('clean(input)')],
 ['unknown-props','UNKNOWN',view('storedValue')],
 ['custom-container','UNKNOWN','const V=()=> <Custom dangerouslySetInnerHTML={{__html:"fixed"}}/>;'],
 ['script-text','UNKNOWN',"const box=document.createElement('script');box.textContent=externalValue;"],
 ['active-literal','UNKNOWN',view("'<img src=x onerror=run()>'")],
 ['purify-config','UNKNOWN',"import DOMPurify from 'dompurify';"+view('DOMPurify.sanitize(input,externalConfig)')],
])xss25Cases.push({id:'xss-'+id,truth,code,filePath:'view.tsx',grade:'B_SAME_AUTHOR_NOT_BLIND'});

export const ssrf25Cases=[];
const server=(body,setup="const http=require('node:http');",extra=[])=>({files:[{filePath:'server.cjs',content:`const app=require('express')();${setup}app.post('/proxy',(req,res)=>{${body}});`},...extra],nodeManifests:[{filePath:'package.json',express:'4.18.0'}]});
for(const [id,truth,body,setup]of [
 ['get','RISK','http.get(req.body.url);'],
 ['alias','RISK','const get=http.get;get(req.query.url);'],
 ['helper','RISK','function forward(u){http.get(u)}forward(req.body.url);'],
 ['absolute-base','RISK',"http.get(new URL(req.body.url,'http://a.example.invalid/'));"],
 ['host','RISK',"http.get('http://'+req.body.host+'/path');"],
 ['https','RISK','http.get(req.body.url);',"const http=require('node:https');"],
 ['esm','RISK','forward(req.body.url);',"import {get as forward} from 'node:http';"],
 ['mixed-alias','RISK',"const input=req.body.url;const u=req.body.flag?'http://a.example.invalid/':input;http.get(u);"],
 ['fixed','NORMAL',"http.get('http://a.example.invalid/');"],
 ['fixed-path','NORMAL',"http.get('http://a.example.invalid/files/'+req.body.name);"],
 ['choices','NORMAL',"const u=req.body.flag?'http://a.example.invalid/':'http://b.example.invalid/';http.get(u);"],
 ['allowed','NORMAL',"const u=new URL(req.body.url);if(u.protocol!=='http:'||u.hostname!=='a.example.invalid')return;http.get(u);"],
 ['sequential-allowed','NORMAL',"const u=new URL(req.body.url);if(u.protocol!=='http:')return;if(u.hostname!=='a.example.invalid')return;http.get(u);"],
 ['fake','NORMAL',"const other={get(x){return x}};other.get(req.body.url);"],
 ['options','UNKNOWN','http.get({hostname:req.body.host,path:"/"});'],
 ['extra-options','UNKNOWN',"http.get(req.body.url,{lookup:externalLookup});"],
 ['callback','UNKNOWN','http.get(req.body.url,()=>{});'],
 ['mutated','UNKNOWN','http.get=external;http.get(req.body.url);'],
 ['hostname-only','UNKNOWN',"const u=new URL(req.body.url);if(u.hostname!=='a.example.invalid')return;http.get(u);"],
 ['prefix','UNKNOWN',"if(!req.body.url.startsWith('http://a.example.invalid'))return;http.get(req.body.url);"],
 ['guard-mutation','UNKNOWN',"const u=new URL(req.body.url);if(u.protocol!=='http:'||u.hostname!=='a.example.invalid')return;u.href=req.body.other;http.get(u);"],
 ['request-not-get','UNKNOWN','http.request(req.body.url);'],
])ssrf25Cases.push({id:'ssrf-'+id,truth,...(id==='allowed'?{knownGap:'Logical OR guard still merges the native receiver conservatively; normal truth is retained, not TN.'}:{}),input:server(body,setup),grade:'B_SAME_AUTHOR_NOT_BLIND'});
export const sqlBranch25={files:[{filePath:'server.cjs',content:"const app=require('express')();const E=require('sequelize');const db=new E('unused');app.post('/',(req,res)=>{const field=req.body.order==='name'?'name':'id';db.query({query:'SELECT '+field+' FROM items'});});"}],nodeManifests:[{filePath:'package.json',express:'4.18.0',sequelize:'6.37.5'}]};
