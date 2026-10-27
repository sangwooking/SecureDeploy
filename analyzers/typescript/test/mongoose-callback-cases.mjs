// Grade B development matrix: API/version controls, not independent applications.
import {mongooseInput} from './mongoose-cases.mjs';
const make=(id,truth,body,options={},count=truth==='RISK'?1:0)=>({id,truth,count,input:mongooseInput(body,options)});
export const callbackCases=[];
for(const major of [4,5,6]){
  const version=major+'.13.0';
  callbackCases.push(
    make('v'+major+'-direct','RISK','Model.findOne({email:req.body.email},function(err,row){});',{version}),
    make('v'+major+'-find','RISK','Model.find({email:req.query.email},(err,rows)=>{});',{version}),
    make('v'+major+'-exec','RISK','const q=Model.findOne({email:req.body.email});q.exec((err,row)=>{});',{version}),
    make('v'+major+'-optional','RISK',"const done=(err,row)=>{};Model.findOne({email:req.body.email},'email name',{},done);",{version})
  );
}
for(const major of [7,8])for(const form of ['findOne','find','exec']){
  const body=form==='exec'?'Model.findOne({email:req.body.email}).exec((err,row)=>{});'
    :'Model.'+form+'({email:req.body.email},(err,row)=>{});';
  callbackCases.push(make('v'+major+'-'+form,'UNSUPPORTED',body,{version:major+'.3.0'}));
}
callbackCases.push(
  make('String-defense','NORMAL','Model.findOne({email:String(req.body.email)},(err,row)=>{});'),
  make('known-toString','NORMAL','Model.findOne({email:String(req.body.email).toString()},(err,row)=>{});'),
  make('fixed-filter','NORMAL',"Model.find({email:'constant@example.invalid'},(err,row)=>{});"),
  make('sanitize-option','DEFENDED','Model.findOne({email:req.body.email},null,{sanitizeFilter:true},(err,row)=>{});'),
  make('sanitize-exec','DEFENDED','Model.findOne({email:req.body.email}).setOptions({sanitizeFilter:true}).exec((err,row)=>{});'),
  make('sanitize-global','DEFENDED','Model.findOne({email:req.body.email},(err,row)=>{});',{setup:"m.set('sanitizeFilter',true);"}),
  make('strict-query','RISK',"Model.findOne({email:req.body.email},null,{strictQuery:true},(err,row)=>{});"),
  make('old-sanitize','UNKNOWN','Model.findOne({email:req.body.email},null,{sanitizeFilter:true},(err,row)=>{});',{version:'5.13.0'}),
  make('trusted','UNKNOWN','Model.findOne({email:m.trusted(req.body.email)},null,{sanitizeFilter:true},(err,row)=>{});'),
  make('unknown-input','UNKNOWN','Model.findOne({email:externalValue()},(err,row)=>{});'),
  make('unknown-toString','UNKNOWN','Model.findOne({email:req.body.email.toString()},(err,row)=>{});'),
  make('unknown-model','UNKNOWN','Model.findOne({email:req.body.email},(err,row)=>{});',{define:'const Model=externalModel();'}),
  make('unknown-callback','UNKNOWN','const done=externalCallback();Model.findOne({email:req.body.email},done);'),
  make('unknown-exec','UNKNOWN','const q=Model.findOne({email:req.body.email});q.exec(externalCallback());'),
  make('callback-data','CREATED',"const callback='email';Model.findOne({email:req.body.email},callback);"),
  make('callback-object','UNKNOWN','const callback={};Model.findOne({email:req.body.email},null,{},callback);'),
  make('wrong-position','UNKNOWN','await Model.findOne({email:req.body.email},()=>{},{});'),
  make('ambiguous-function','UNKNOWN','const cb=req.body.flag?()=>{}:function(){};Model.findOne({email:req.body.email},cb);'),
  make('repeat-exec','RISK','const q=Model.findOne({email:req.body.email});const done=()=>{};q.exec(done);q.exec(done);'),
  make('callback-await','RISK','const q=Model.findOne({email:req.body.email},()=>{});await q;'),
  make('await-exec-callback','RISK','await Model.findOne({email:req.body.email}).exec(()=>{});'),
  make('promise-repeat','RISK','const q=Model.findOne({email:req.body.email});await q;await q;'),
  make('separate-queries','RISK','Model.findOne({email:req.body.first},()=>{});Model.findOne({email:req.body.second},()=>{});',{},2),
  make('function-alias','RISK','const done=()=>{};const alias=done;Model.findOne(req.body,alias);'),
  make('unconsumed','CREATED','Model.findOne(req.body);'),
  make('ordinary-api','UNKNOWN','const Model={findOne(value,cb){return value;}};Model.findOne({email:req.body.email},()=>{});',{define:''}),
  make('callback-body-not-run','RISK',"Model.findOne({email:req.body.email},()=>{eval(req.body.code);});"),
  make('effects-after-defended','UNKNOWN',"Model.findOne({email:req.body.first},()=>{m.set('sanitizeFilter',false);});await Model.findOne({email:req.body.second});",{setup:"m.set('sanitizeFilter',true);"}),
  make('unsupported-exec-op','UNKNOWN',"Model.findOne(req.body).exec('findOne',()=>{});"),
  make('exec-extra','UNKNOWN','Model.findOne(req.body).exec(()=>{},{});'),
  make('filter-mutated','UNKNOWN',"const f={email:req.body.email};const q=Model.findOne(f);f.email='constant';q.exec(()=>{});"),
  make('callback-import','RISK',"const done=require('./done.cjs');Model.findOne(req.body,done);",{more:[{filePath:'done.cjs',content:'module.exports=function done(err,result){};'}]}),
);
for(const version of ['latest','>=4 <8','6.x'])callbackCases.push(make('version-'+version.replace(/\W/g,'_'),'UNKNOWN',
  'Model.findOne({email:req.body.email},()=>{});',{version}));
