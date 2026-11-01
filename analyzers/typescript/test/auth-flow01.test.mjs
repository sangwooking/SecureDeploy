import{test}from'node:test';import assert from'node:assert/strict';import{analyze}from'../analyzer.mjs';
const setup=`import express from 'express';import{MongoClient}from'mongodb';const app=express();const client=new MongoClient('mongodb://fixture.invalid');const records=client.db('owned').collection('records');`;
function run(body,extra=[]){return analyze({files:[{filePath:'app.mjs',content:setup+`app.get('/records/:id',(req,res)=>{${body}});`},...extra],nodeManifests:[{filePath:'package.json',express:'5.1.0',mongodb:'6.12.0'}]});}
test('Mongo request key and principal reference remain separate observations, not authentication proof',()=>{
 for(const call of['findOne','deleteOne','updateOne']){
  const r=run(`records.${call}({_id:req.params.id,holder:req.user.id}${call==='updateOne'?",{$set:{label:'x'}}":''});`),d=r.authorizationContexts[0].details;
  assert.equal(d.authenticationStatus,'UNKNOWN');assert.equal(d.objectAuthorizationStatus,'OWNER_POLICY_REVIEW_REQUIRED');assert.ok(d.principalReferences.length);assert.ok(d.accesses[0].identifierInputs.length);assert.equal(d.accesses[0].conclusion,'REQUEST_KEYED_DB_POLICY_REVIEW_REQUIRED');assert.equal(r.findings.filter(f=>/AUTHORIZATION|IDOR/.test(f.ruleId)).length,0);
 }
});
test('query and body IDs reach actual MongoDB library access without user-ID conflation',()=>{
 for(const field of['query','body']){const r=run(`const key=req.${field}.key;records.findOne({_id:key});`),d=r.authorizationContexts[0].details;assert.equal(d.principalReferences.length,0);assert.equal(d.accesses[0].identifierInputs[0].kind,'EXPRESS_'+field.toUpperCase());}
});
test('cross-file service parameters retain actual DB call location',()=>{
 const r=run(`load(records,req.params.id,req.user);`,[{filePath:'service.mjs',content:'export function load(db,key,user){return db.findOne({_id:key,holder:user.id});}'}].map(x=>x));
 // Unimported helper is unresolved, never inferred by name.
 assert.equal(r.authorizationContexts[0].details,undefined);
 const imported=analyze({files:[{filePath:'app.mjs',content:`import{load}from'./service.mjs';`+setup+`app.get('/records/:id',(req,res)=>{load(records,req.params.id,req.user);});`},{filePath:'service.mjs',content:'export function load(db,key,user){return db.findOne({_id:key,holder:user.id});}'}],nodeManifests:[{filePath:'package.json',express:'5.1.0',mongodb:'6.12.0'}]});
 const d=imported.authorizationContexts[0].details;assert.equal(d.accesses[0].location.filePath,'service.mjs');assert.equal(d.accesses[0].identifierInputs[0].filePath,'app.mjs');assert.ok(d.principalReferences.length);
});
test('constant public lookup and unrecognized database do not manufacture an authorization Finding',()=>{
 const r=run(`records.findOne({_id:'public'});`);assert.equal(r.authorizationContexts[0].details.accesses[0].conclusion,'OBJECT_AUTHORIZATION_NOT_ESTABLISHED');assert.equal(r.authorizationContexts[0].details.objectAuthorizationStatus,'NOT_ESTABLISHED');
 const unknown=run(`const fake=resolveDatabase();fake.findOne({_id:req.params.id});`);assert.equal(unknown.authorizationContexts[0].details,undefined);
});
test('Next Pages complex DB initialization remains explicitly unsupported',()=>{
 const r=analyze({files:[{filePath:'pages/api/record.ts',content:`import{MongoClient}from'mongodb';const client=new MongoClient('mongodb://fixture.invalid');const records=client.db('owned').collection('records');export default function handler(req,res){records.findOne({_id:req.query.id});}`}],nodeManifests:[{filePath:'package.json',next:'15.2.0',mongodb:'6.12.0'}]});assert.equal(r.authorizationContexts.length,0);assert.ok(r.files[0].limitations.includes('STATIC_HANDLER_INITIALIZATION_NOT_SUPPORTED'));
});
