import {analyze,VERSION} from '../../analyzers/typescript/analyzer.mjs';
// Audit existing behavior only. No synthetic bootstrap is inserted into product input.
export const routeDiscoveryCases=[
 {id:'standalone-module-no-listen',files:[{filePath:'detached.js',content:`const app=require('express')();app.post('/',(req,res)=>eval(req.body.code));`}]},
 {id:'uncalled-registration-factory',files:[{filePath:'detached.js',content:`const app=require('express')();module.exports=()=>app.post('/',(req,res)=>eval(req.body.code));`}]},
 {id:'unmounted-router',files:[{filePath:'detached.js',content:`const router=require('express').Router();router.post('/',(req,res)=>eval(req.body.code));module.exports=router;`}]},
 {id:'called-mounted-factory',files:[{filePath:'entry.js',content:`const express=require('express');const app=express();function routes(){const r=express.Router();r.post('/',(req,res)=>eval(req.body.code));return r;}app.use('/api',routes());`}]},
 {id:'uninvoked-event-listener',files:[{filePath:'entry.js',content:`const app=require('express')();external.on('ready',()=>app.post('/',(req,res)=>eval(req.body.code)));`}]},
];
export function auditRouteDiscovery(){return routeDiscoveryCases.map(c=>{const r=analyze({files:c.files});return {id:c.id,entries:r.files.reduce((n,f)=>n+f.entrypoints,0),findings:r.findings.map(f=>({ruleId:f.ruleId,confidence:f.confidence,source:f.source,sink:f.sink})),registration:r.nodeUses.filter(u=>u.kind==='ENTRY_REGISTERED'),limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort()};});}
if(process.argv[1]?.endsWith('/routefirst35.mjs'))console.log(JSON.stringify({worker:VERSION,scope:'NON_BLIND_EXISTING_BEHAVIOR_AUDIT_NOT_ROUTE_FIRST_IMPLEMENTATION',cases:auditRouteDiscovery()},null,2));
