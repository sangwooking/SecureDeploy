import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {web27Cases} from './web27-cases.mjs';
const rule='JS_CORS_CREDENTIAL_REFLECTION';
const packet=(setup,body="res.json({value:process.env.SERVICE_ROLE_KEY});",tail='')=>({files:[{filePath:'server.cjs',content:`const app=require('express')();const cors=require('cors');const session=require('express-session');const fs=require('fs');${setup}app.post('/work',(req,res)=>{${body}});${tail}`}],nodeManifests:[{filePath:'package.json',express:'4.18.0',cors:'2.8.5','express-session':'1.18.1'}]});
const hits=r=>r.findings.filter(f=>f.ruleId===rule);
const policy='app.use(cors({origin:true,credentials:true}));';
for(const c of web27Cases)test('web27 frozen control '+c.id,()=>{
 const r=analyze(c.input);assert.deepEqual(r,analyze(c.input));
 const selected=r.findings.filter(f=>[rule,'JS_SESSION_COOKIE_ATTRIBUTE_REVIEW'].includes(f.ruleId));
 assert.equal(selected.length,['cookie-no-httponly','cookie-route-session'].includes(c.id)?1:0);
 assert.ok(!r.findings.some(f=>f.ruleId==='JS_CSRF_INPUT_FLOW'));
});
test('supported secret Source connects CORS scope to actual terminal response',()=>{
 for(const setup of [policy,"const options={origin:true,credentials:true};app.use(cors(options));","app.use('/work',cors({origin:true,credentials:true}));"]){
  const r=analyze(packet(setup));assert.equal(hits(r).length,1);
  const f=hits(r)[0];assert.equal(f.kind,'CWE-942');assert.equal(f.disposition,'REVIEW_REQUIRED');
  assert.ok(f.flow.some(l=>l.kind==='SERVER_SECRET_ENVIRONMENT_VALUE'));
  assert.equal(f.sink.kind,'WEB_HTTP_RESPONSE');
 }
});
test('scope, order, mutation, versions and unknown middleware cannot create a confident CORS path',()=>{
 for(const [setup,body,tail]of [
  ['',undefined,policy],["app.use('/other',cors({origin:true,credentials:true}));"],
  [policy+'app.use(externalGate);'],[policy+policy],
  ["const options={origin:true,credentials:true};app.use(cors(options));options.origin=external;"],
  [policy,"res.setHeader('Access-Control-Allow-Origin',external);res.json({value:process.env.SERVICE_ROLE_KEY});"],
  [policy,"function headers(r){r.setHeader('Access-Control-Allow-Origin',external)}headers(res);res.json({value:process.env.SERVICE_ROLE_KEY});"],
  ["const cors=external;app.use(cors({origin:true,credentials:true}));"],
  ["app.use(cors({origin:externalCheck,credentials:true}));"],
  [policy,"res.json({public:true});"],
  [policy,"res.status(204).json({value:process.env.SERVICE_ROLE_KEY});"],
  [policy,"res.json(200,{value:process.env.SERVICE_ROLE_KEY});"],
 ])assert.equal(hits(analyze(packet(setup,body,tail))).length,0,setup);
 for(const version of ['2.8.6','1.0.0',undefined]){
  const input=packet(policy);input.nodeManifests[0].cors=version;assert.equal(hits(analyze(input)).length,0);
 }
 const limited=analyze(packet(policy),{maxSteps:2});assert.equal(hits(limited).length,0);
});
test('route-local middleware and later irrelevant mounts do not change earlier route scope',()=>{
 const input=packet('',undefined,'app.use(external);');
 input.files[0].content=input.files[0].content.replace("app.post('/work',","app.post('/work',cors({origin:true,credentials:true}),");
 assert.equal(hits(analyze(input)).length,1);
});
test('cookie declarations do not imply authentication, lifecycle or TLS success',()=>{
 const setup="app.use(session({secret:process.env.SESSION_SECRET,cookie:{secure:true,httpOnly:false,sameSite:'none'}}));";
 const r=analyze(packet(setup,"const current=req.session;res.end('ok');"));
 const f=r.findings.find(f=>f.ruleId==='JS_SESSION_COOKIE_ATTRIBUTE_REVIEW');assert.ok(f);
 assert.ok(f.limitations.includes('SESSION_COOKIE_REFERENCE_NOT_AUTHENTICATION_SUCCESS'));
 assert.ok(f.limitations.includes('PROXY_TLS_AND_DEPLOYMENT_UNKNOWN'));
 for(const change of ["const current=external;res.end('ok');","res.cookie('theme','dark',{httpOnly:false});res.end('ok');"])
  assert.ok(!analyze(packet(setup,change)).findings.some(f=>f.ruleId==='JS_SESSION_COOKIE_ATTRIBUTE_REVIEW'));
 const serialized=JSON.stringify(r);assert.ok(!serialized.includes('SESSION_SECRET'));assert.ok(!serialized.includes('node_modules'));
});
test('only exact early Origin rejection is recorded; unknown calls are not read-only proof',()=>{
 const setup="app.use(session({secret:process.env.SESSION_SECRET,cookie:{secure:true,httpOnly:true}}));";
 const write="const current=req.session;fs.writeFileSync('/owned/state','changed');res.end('ok');";
 const guard="if(req.get('origin')!=='https://trusted.invalid')return res.status(403).end();";
 assert.ok(analyze(packet(setup,guard+write)).nodeUses.some(u=>u.kind==='CSRF_EXACT_ORIGIN_CONSTRAINT'));
 for(const body of [write+guard,"const unknown=externalWrite();"+write,"if(external)return;"+guard+write]){
  const r=analyze(packet(setup,body));
  assert.ok(!r.nodeUses.some(u=>['CSRF_READ_ONLY_LOCAL_BODY','CSRF_EXACT_ORIGIN_CONSTRAINT'].includes(u.kind)));
  assert.ok(!r.findings.some(f=>f.ruleId==='JS_CSRF_INPUT_FLOW'));
 }
});
