// Authored development/validation contracts, not independent real-CVE truth.
import {mongooseInput} from './mongoose-cases.mjs';
export const injection24Cases=[];
const sqlInput=(body,version)=>({files:[{filePath:'server.cjs',content:`const express=require('express');const E=require('sequelize');const db=new E('unused');const app=express();app.post('/lookup',(req,res)=>{${body}});`}],nodeManifests:[{filePath:'package.json',express:'4.18.0',sequelize:version}]});
const sql=[
 ['direct','RISK',"db.query('SELECT * FROM items WHERE id='+req.body.id);"],
 ['object-concat','RISK',"db.query({query:'SELECT * FROM items WHERE id='+req.body.id});"],
 ['object-template','RISK','db.query({query:`SELECT * FROM items WHERE id=${req.body.id}`});'],
 ['object-alias','RISK',"const q={query:'SELECT * FROM items WHERE id='+req.body.id};const alias=q;db.query(alias);"],
 ['object-helper','RISK',"function build(x){return {query:'SELECT * FROM items WHERE id='+x}}db.query(build(req.body.id));"],
 ['binding-after-concat','RISK',"db.query({query:'SELECT * FROM items WHERE id='+req.body.id+' AND kind=$1',bind:['fixed']});"],
 ['bound-string','NORMAL',"db.query('SELECT * FROM items WHERE id=$1',{bind:[req.body.id]});"],
 ['values-object','NORMAL',"db.query({query:'SELECT * FROM items WHERE id=?',values:[req.body.id]});"],
 ['bind-object','NORMAL',"db.query({query:'SELECT * FROM items WHERE id=$1',bind:[req.body.id]});"],
 ['static-object','NORMAL',"db.query({query:'SELECT 1'});"],
 ['selected-fixed','NORMAL',"const field=req.body.order==='name'?'name':'id';db.query({query:'SELECT '+field+' FROM items'});"],
 ['unknown-query','UNKNOWN',"db.query({query:externalSql(req.body.id)});"],
 ['spread','UNKNOWN',"db.query({...externalOptions(),query:'SELECT * FROM items WHERE id='+req.body.id});"],
 ['conflicting-values','UNKNOWN',"db.query({query:'SELECT * FROM items WHERE id='+req.body.id,values:[req.body.id]},{replacements:[req.body.id]});"],
 ['mixed-bindings','UNKNOWN',"db.query({query:'SELECT * FROM items WHERE id='+req.body.id,values:[req.body.id],bind:[req.body.id]});"],
 ['missing-query','UNKNOWN',"db.query({unrecognized:req.body.id});"],
 ['dynamic-wrapper','UNKNOWN',"externalWrapper(db,req.body.id);"],
];
for(const version of ['4.44.4','5.22.5','6.37.5'])for(const [id,truth,body]of sql)
 injection24Cases.push({id:'sql-'+version+'-'+id,track:'SQL',truth,split:version==='4.44.4'?'REGRESSION':'VALIDATION_SAME_AUTHOR_NOT_BLIND',
  ...(id==='selected-fixed'?{knownGap:'Constant identifier alternatives are a normal control, but no SQL execution observation is connected after this conditional expression.'}:{}),input:sqlInput(body,version)});
const mongo=[
 ['direct','RISK','await Model.findOne({email:req.body.email});'],
 ['shared-body','RISK','const x=req.body;await Model.findOne({email:x,password:x});'],
 ['shared-callback','RISK','const x=req.body;Model.findOne({email:x,password:x},()=>{});'],
 ['shared-exec','RISK','const x=req.body;Model.findOne({email:x,password:x}).exec();'],
 ['shared-helper','RISK','function make(x){return {email:x,password:x}}await Model.findOne(make(req.body));'],
 ['constant-alias','NORMAL',"const x='fixed';await Model.findOne({email:x,password:x});"],
 ['constant-direct','NORMAL',"await Model.findOne({email:'fixed'});"],
 ['string-reused','NORMAL','const x=String(req.body.email);await Model.findOne({email:x,password:x});'],
 ['type-guard','NORMAL',"const x=req.body.email;if(typeof x!=='string')return;await Model.findOne({email:x,password:x});"],
 ['sanitize','NORMAL','await Model.findOne({email:req.body.email},null,{sanitizeFilter:true});'],
 ['trusted-static-other-field','NORMAL',"const fixed=m.trusted({marker:'fixed'});await Model.findOne({serverOnly:fixed,email:req.body.email},null,{sanitizeFilter:true,strictQuery:true});"],
 ['unknown-transform','UNKNOWN','await Model.findOne({email:external(req.body.email)});'],
 ['trusted-input','UNKNOWN','await Model.findOne({email:m.trusted(req.body.email)},null,{sanitizeFilter:true});'],
 ['filter-mutation','UNKNOWN',"const f={email:req.body.email};const q=Model.findOne(f);f.email='fixed';await q;"],
 ['dynamic-filter','UNKNOWN','await Model.findOne({[req.body.key]:req.body.email});'],
 ['creation-only','UNKNOWN','Model.findOne({email:req.body.email});'],
];
for(const [id,truth,body]of mongo)injection24Cases.push({id:'mongo-'+id,track:'NOSQL',truth,split:'REGRESSION_SAME_AUTHOR',input:mongooseInput(body,{version:'6.13.0',define:"const Model=m.model('Record',new m.Schema({email:String,password:String}));"})});
