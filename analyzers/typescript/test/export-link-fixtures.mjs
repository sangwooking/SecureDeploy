// Authored structure controls, frozen before the export-link implementation.
// These are not upstream CVEs, real applications, or independent holdout cases.
const file=(filePath,content)=>({filePath,content});
const worker=body=>`export default {async fetch(request,env){${body}}};`;
const input=`const id=new URL(request.url).searchParams.get('id');`;
const sql=(body,exported='export {query};')=>file('service.ts',`function query(db,id){${body}} ${exported}`);
const route=spec=>file('worker.ts',`import {query} from '${spec}';${worker(input+'return query(env.DB,id);')}`);
export const exportLinkCases=[
 {id:'direct-sql-reference',truth:'DANGEROUS',rule:'TS_SQL_INPUT_FLOW',files:[route('./service'),sql(`return db.prepare('SELECT * FROM item WHERE id='+id).all();`,'export {query};')],newContract:true},
 {id:'local-function-alias',truth:'DANGEROUS',rule:'TS_SQL_INPUT_FLOW',files:[route('./service'),file('service.ts',`function build(db,id){return db.prepare(id).run();}export {build as query};`)]},
 {id:'local-const-function',truth:'DANGEROUS',rule:'TS_SQL_INPUT_FLOW',files:[route('./service'),file('service.ts',`const query=(db,id)=>db.prepare(id).first();export {query};`)]},
 {id:'named-barrel-alias',truth:'DANGEROUS',rule:'TS_SQL_INPUT_FLOW',files:[route('./api'),file('api.ts',`export {query as query} from './service';`),sql(`return db.prepare(id).first();`)]},
 {id:'default-function-forward',truth:'DANGEROUS',rule:'TS_SQL_INPUT_FLOW',files:[route('./api'),file('api.ts',`export {default as query} from './service';`),file('service.ts',`export default function execute(db,id){return db.prepare(id).run();}`)]},
 {id:'ssrf-return-forward',truth:'DANGEROUS',rule:'TS_SSRF_INPUT_FLOW',files:[file('worker.ts',`import {proxy} from './api';${worker(input+'return proxy(id);')}`),file('api.ts',`export {proxy} from './service';`),file('service.ts',`async function proxy(url){return fetch(url);}export {proxy};`)]},
 {id:'deno-environment-response',truth:'DANGEROUS',rule:'TS_SENSITIVE_DATA_EXPOSURE',files:[file('edge.ts',`import {reply} from './service';Deno.serve(request=>reply(Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')));`),file('service.ts',`function reply(value){return Response.json({status:'ok',diagnostic:value});}export {reply};`)]},
 {id:'express-handler-export',truth:'DANGEROUS',rule:'JS_SHELL_COMMAND_INPUT_FLOW',files:[file('boot.mjs',`import express from 'express';import {handler} from './service.mjs';const app=express();app.get('/task',handler);`),file('service.mjs',`import {exec} from 'node:child_process';function handler(req,res){exec(req.query.task);}export {handler};`)]},
 {id:'bound-value',truth:'NORMAL',rule:'TS_SQL_INPUT_FLOW',files:[route('./api'),file('api.ts',`export {query} from './service';`),sql(`return db.prepare('SELECT * FROM item WHERE id=?').bind(id).first();`)]},
 {id:'unused-input',truth:'NORMAL',rule:'TS_SQL_INPUT_FLOW',files:[route('./service'),sql(`return db.prepare('SELECT 1').first();`)]},
 {id:'overwrite-input',truth:'NORMAL',rule:'TS_SQL_INPUT_FLOW',files:[route('./service'),sql(`id='fixed';return db.prepare(id).first();`)]},
 {id:'fixed-destination',truth:'NORMAL',rule:'TS_SSRF_INPUT_FLOW',files:[file('worker.ts',`import {proxy} from './service';${worker(input+'return proxy(id);')}`),file('service.ts',`function proxy(input){return fetch('https://example.invalid/health');}export {proxy};`)]},
 {id:'environment-kept-internal',truth:'NORMAL',rule:'TS_SENSITIVE_DATA_EXPOSURE',files:[file('edge.ts',`import {reply} from './service';Deno.serve(request=>reply(Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')));`),file('service.ts',`function reply(value){return Response.json({status:'ok'});}export {reply};`)]},
 {id:'type-only-export',truth:'UNKNOWN',rule:'TS_SQL_INPUT_FLOW',files:[route('./api'),file('api.ts',`export type {query} from './service';`),sql(`return db.prepare(id).run();`)]},
 {id:'missing-forward-target',truth:'UNKNOWN',rule:'TS_SQL_INPUT_FLOW',files:[route('./api'),file('api.ts',`export {query} from './missing';`)]},
 {id:'wildcard-unresolved',truth:'UNKNOWN',rule:'TS_SQL_INPUT_FLOW',files:[route('./api'),file('api.ts',`export * from './service';`),sql(`return db.prepare(id).run();`)]},
 {id:'reexport-cycle',truth:'UNKNOWN',rule:'TS_SQL_INPUT_FLOW',files:[route('./api'),file('api.ts',`export {query} from './other';`),file('other.ts',`export {query} from './api';`)]},
 {id:'mutable-export',truth:'UNKNOWN',rule:'TS_SQL_INPUT_FLOW',files:[route('./service'),file('service.ts',`let query=(db,id)=>db.prepare(id).run();query=external;export {query};`)]},
 {id:'unmounted-exported-handler',truth:'NORMAL',rule:'JS_SHELL_COMMAND_INPUT_FLOW',files:[file('service.mjs',`import {exec} from 'node:child_process';function handler(req,res){exec(req.query.task);}export {handler};`)]},
];
