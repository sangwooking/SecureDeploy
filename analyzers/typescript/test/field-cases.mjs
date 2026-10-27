// Authored development controls. Field names are variations, never rule keys.
export function fieldInput(body,{version='^13.5.2',setup='',define="const Model=m.model('Account',new m.Schema({login:String,pass:String}));",library="const checks=require('validator');"}={}){
  return {nodeManifests:[{filePath:'package.json',mongoose:'4.2.4',express:'4.18.0',validator:version}],files:[{filePath:'server.cjs',
    content:"const express=require('express');const m=require('mongoose');"+library+define+"const app=express();"+setup+"app.post('/session',async(req,res)=>{\n"+body+"\nres.end('ok');});"}]};
}
const query="Model.findOne({login:req.body.contact,pass:req.body.credential},()=>{});";
const typeChecks="if(typeof req.body.contact!=='string')return;if(typeof req.body.credential!=='string')return;";
const c=(id,truth,body,options={},source='req.body.credential')=>({id,truth,source,input:fieldInput(body,options)});
export const fieldCases=[
  c('format-one-field','RISK','if(checks.isEmail(req.body.contact)){'+query+'}'),
  c('early-return','RISK','if(!checks.isEmail(req.body.contact))return;'+query),
  c('field-aliases','RISK','const u=req.body.contact;const p=req.body.credential;if(checks.isEmail(u))Model.findOne({login:u,pass:p},()=>{});'),
  c('body-alias','RISK','const data=req.body;const u=data.contact;if(checks.isEmail(u))Model.findOne({login:data.contact,pass:data.credential},()=>{});',{},'data.credential'),
  c('boolean-alias','RISK','const valid=checks.isEmail(req.body.contact);if(valid){'+query+'}'),
  c('negated-alias','RISK','const invalid=!checks.isEmail(req.body.contact);if(invalid)return;'+query),
  c('reverse-branch','RISK','if(!checks.isEmail(req.body.contact)){'+query+'}'),
  c('parentheses','RISK','if((checks.isEmail(req.body.contact))){'+query+'}'),
  c('type-one-field','RISK',"if(typeof req.body.contact==='string'){"+query+'}'),
  c('similar-field-names','RISK','if(checks.isEmail(req.body.mail))Model.findOne({login:req.body.mailExtra},()=>{});',{},'req.body.mailExtra'),
  c('different-container','RISK','if(checks.isEmail(req.body.contact))Model.findOne({login:req.query.contact},()=>{});',{},'req.query.contact'),
  c('reassigned-alias','RISK',"let u=req.body.contact;if(typeof u==='string'){u=req.body.credential;Model.findOne({pass:u},()=>{});}"),
  {...c('nondominating-type','RISK',"if(typeof req.body.credential==='string'){}Model.findOne({pass:req.body.credential},()=>{});"),
    expectedState:'UNKNOWN',knownGap:'Existing branch heap merge loses the callback version proof; the unsafe source truth is unchanged.'},
  c('both-strings','NORMAL',typeChecks+query),
  c('both-strings-and-format','NORMAL',typeChecks+'if(checks.isEmail(req.body.contact)){'+query+'}'),
  c('typed-aliases','NORMAL',"const a=req.body.contact;const b=req.body.credential;if(typeof a!=='string')return;if(typeof b!=='string')return;Model.findOne({login:a,pass:b},()=>{});"),
  c('constant-query','NORMAL',"if(checks.isEmail(req.body.contact))Model.findOne({login:'fixed',pass:'fixed'},()=>{});"),
  c('literal-unreachable','UNREACHABLE','if(false){if(checks.isEmail(req.body.contact)){'+query+'}}'),
  c('format-only','UNKNOWN','if(checks.isEmail(req.body.contact))Model.findOne({login:req.body.contact},()=>{});'),
  c('one-type-one-format','UNKNOWN',"if(typeof req.body.credential!=='string')return;if(checks.isEmail(req.body.contact)){"+query+'}'),
  c('unknown-library','UNKNOWN','if(checks.isEmail(req.body.contact)){'+query+'}',{library:'const checks=externalValidator();'}),
  c('unknown-version','UNKNOWN','if(checks.isEmail(req.body.contact)){'+query+'}',{version:'latest'}),
  c('wrong-package','UNKNOWN','if(checks.isEmail(req.body.contact)){'+query+'}',{library:"const checks=require('./custom-validator');"}),
  c('mutated-validator','UNKNOWN','checks.isEmail=replacement;if(checks.isEmail(req.body.contact)){'+query+'}'),
  c('options-outside-contract','UNKNOWN','if(checks.isEmail(req.body.contact,{allow_display_name:true})){'+query+'}'),
  c('dynamic-field','UNKNOWN','if(checks.isEmail(req.body[req.body.key])){'+query+'}'),
  c('nested-field','UNKNOWN','if(checks.isEmail(req.body.profile.contact)){'+query+'}'),
  c('complex-and','UNKNOWN','if(checks.isEmail(req.body.contact)&&externalCheck(req.body.credential)){'+query+'}'),
  c('complex-type-and','UNKNOWN',"if(typeof req.body.contact==='string'&&typeof req.body.credential==='string'){"+query+'}'),
  c('unknown-call-after-guard','UNKNOWN','if(!checks.isEmail(req.body.contact))return;externalWork();'+query),
  c('request-write-after-guard','UNKNOWN','if(!checks.isEmail(req.body.contact))return;req.body.contact=req.body.credential;'+query),
  c('helper-outside-scope','UNKNOWN','function lookup(){'+query+'}if(checks.isEmail(req.body.contact))lookup();'),
  c('unknown-model','UNKNOWN','if(checks.isEmail(req.body.contact)){'+query+'}',{define:'const Model=externalModel();'}),
  c('creation-only','CREATED','if(checks.isEmail(req.body.contact))Model.findOne({pass:req.body.credential});'),
  c('ordinary-model-api','UNRELATED','if(checks.isEmail(req.body.contact)){'+query+'}',{define:'const Model={findOne(value,cb){return value;}};'}),
  c('ternary-format','UNKNOWN',"const a=checks.isEmail(req.body.contact)?req.body.contact:'fixed';Model.findOne({login:a},()=>{});"),
];
