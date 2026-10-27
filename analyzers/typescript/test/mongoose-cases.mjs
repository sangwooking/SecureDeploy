// Authored Grade B development cases, not blind or real-CVE ground truth.
const prefix="const express=require('express');const m=require('mongoose');const app=express();";
const model="const Model=m.model('Record',new m.Schema({email:String}));";
export function mongooseInput(body,{version='6.13.0',setup='',define=model,more=[]}={}) {
  return {files:[{filePath:'server.cjs',content:prefix+setup+define+"app.post('/records',async(req,res)=>{\n"+body+"\nres.json({ok:true});});"},...more],
    nodeManifests:[{filePath:'package.json',mongoose:version,express:'4.18.0'}]};
}
const c=(id,truth,body,options={})=>({id,truth,input:mongooseInput(body,options)});
export const mongooseCases=[
  c('whole-body','RISK','await Model.findOne(req.body);'),
  c('body-field','RISK','await Model.findOne({email:req.body.email});'),
  c('local-alias','RISK','const email=req.body.email;await Model.findOne({email});'),
  c('find-exec','RISK','await Model.find({email:req.body.email}).exec();'),
  c('query-alias','RISK','const q=Model.findOne({email:req.body.email});await q;'),
  c('v4-contract','RISK','await Model.findOne({email:req.body.email});',{version:'^4.11.13'}),
  c('fixed','NORMAL',"await Model.findOne({email:'public@example.invalid'});"),
  c('String','NORMAL','await Model.findOne({email:String(req.body.email)});'),
  c('known-toString','NORMAL','await Model.findOne({email:String(req.body.email).toString()});'),
  c('route-string','NORMAL','await Model.findOne({email:req.params.email});'),
  c('overwrite','NORMAL',"let email=req.body.email;email='fixed';await Model.findOne({email});"),
  c('query-option','DEFENDED','await Model.findOne({email:req.body.email},null,{sanitizeFilter:true});'),
  c('setOptions','DEFENDED','await Model.findOne({email:req.body.email}).setOptions({sanitizeFilter:true});'),
  c('global-setting','DEFENDED','await Model.findOne({email:req.body.email});',{setup:"m.set('sanitizeFilter',true);"}),
  c('override-false','RISK','await Model.findOne({email:req.body.email}).setOptions({sanitizeFilter:false});',{setup:"m.set('sanitizeFilter',true);"}),
  c('strict-query-only','RISK','await Model.findOne({email:req.body.email});',{setup:"m.set('strictQuery',true);"}),
  c('unverified-toString','UNKNOWN','await Model.findOne({email:req.body.email.toString()});'),
  c('unknown-transform','UNKNOWN','await Model.findOne({email:normalize(req.body.email)});'),
  c('unknown-after-String','UNKNOWN','await Model.findOne({email:normalize(String(req.body.email))});'),
  c('unknown-source','UNKNOWN','await Model.findOne({email:externalValue()});'),
  c('dynamic-protection','UNKNOWN','await Model.findOne({email:req.body.email});',{setup:"m.set('sanitizeFilter',externalFlag());"}),
  c('old-sanitize','UNKNOWN','await Model.findOne({email:req.body.email},null,{sanitizeFilter:true});',{version:'5.13.0'}),
  c('trusted-exception','UNKNOWN','await Model.findOne({email:m.trusted(req.body.email)}).setOptions({sanitizeFilter:true});'),
  c('root-filter-sanitize','UNKNOWN','await Model.findOne(req.body).setOptions({sanitizeFilter:true});'),
  c('unknown-version','UNKNOWN','await Model.findOne({email:req.body.email});',{version:'latest'}),
  c('registry-missing','UNKNOWN','await Model.findOne({email:req.body.email});',{define:"const Model=m.model('Elsewhere');"}),
  c('unknown-model','UNKNOWN','await Model.findOne({email:req.body.email});',{define:'const Model=externalModel();'}),
  c('spread-filter','UNKNOWN','await Model.findOne({...req.body});'),
  c('dynamic-field','UNKNOWN','await Model.findOne({[req.body.key]:req.body.value});'),
  c('unmodeled-chain','UNKNOWN','await Model.findOne({email:req.body.email}).where(req.body.extra).exec();'),
  c('mutated-model','UNKNOWN','Model.findOne=replacement;await Model.findOne({email:req.body.email});'),
  c('plugin','UNKNOWN','await Model.findOne({email:req.body.email});',{define:"const schema=new m.Schema({email:String});schema.plugin(externalPlugin);const Model=m.model('Record',schema);"}),
  c('ordinary-api','UNRELATED','const Model={findOne(value){return value;}};await Model.findOne({email:req.body.email});',{define:''}),
  c('unconsumed','CREATED','Model.findOne({email:req.body.email});'),
  c('computed-registry','UNKNOWN','await Model.findOne({email:req.body.email});',{define:'const Model=m.model(externalName(),new m.Schema({email:String}));'}),
];
