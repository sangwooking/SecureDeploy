import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
const input=body=>({files:[{filePath:'server.cjs',content:`const app=require('express')();const http=require('node:http');app.post('/',(req,res)=>{${body}});`}],nodeManifests:[{filePath:'package.json',express:'4.18.0'}]});
const guard="const u=new URL(req.body.url);if(u.protocol!=='http:'||u.hostname!=='a.example.invalid')return;";
const before=process.env.SECUREDEPLOY_AUDIT30_STAGE==='before';
const run=body=>analyze(input(body));
const high=r=>r.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH');
test('unchanged HTTP module survives a logical guard, not an API mutation',()=>{
 const normal=run(guard+'http.get(u);');
 assert.equal(normal.httpUses.some(u=>u.kind==='ALLOWLISTED_DESTINATION'),!before);
 for(const change of ['http.get=external;','if(req.body.flag)http.get=external;'])
  assert.equal(high(run(guard+change+'http.get(req.body.url);')).length,0);
});
test('direct href replacement invalidates earlier allowlist and preserves aliases',()=>{
 for(const change of ['u.href=req.body.other;http.get(u);','const alias=u;alias.href=req.body.other;http.get(u);','const alias=u;u.href=req.body.other;http.get(alias.href);']){
  const r=run(guard+change);assert.equal(high(r).length,before?0:1);
  if(!before){assert.ok(r.httpUses.every(u=>u.defenses.length===0));assert.ok(r.files.some(f=>f.limitations.includes('URL_HREF_REPLACED')));}
 }
});
test('fixed replacement and query-only mutation are not destination-control findings',()=>{
 for(const change of ["u.href='http://fixed.example.invalid/';http.get(u);","u.search=req.body.search;http.get(u);"]){
  const r=run(guard+change);assert.equal(high(r).length,0);
  if(!before)assert.ok(r.httpUses.some(u=>['FIXED_DESTINATION','ALLOWLISTED_DESTINATION'].includes(u.kind)));
 }
});
test('unresolved coercions and branch mutations cannot inherit a safe destination',()=>{
 for(const change of ['u.href=externalValue;http.get(u);','u.href=externalHelper(req.body.other);http.get(u);',"if(req.body.flag)u.href=req.body.other;http.get(u);"]){
  const r=run(guard+change);assert.ok(!r.httpUses.some(u=>['FIXED_DESTINATION','ALLOWLISTED_DESTINATION'].includes(u.kind)));
 }
});
test('reusing already guarded source is not promoted to an unguarded destination proof',()=>{
 const r=run("const q=req.body.url;const u=new URL(q);if(u.protocol!=='http:'||u.hostname!=='a.example.invalid')return;u.href=q;http.get(u);");
 assert.equal(high(r).length,0);assert.ok(!r.httpUses.some(u=>['FIXED_DESTINATION','ALLOWLISTED_DESTINATION'].includes(u.kind)));
});
test('a different HTTP source in a branch is not the original native API',()=>{
 const r=run('let get=http.get;if(req.body.flag)get=external;get(req.body.url);');assert.equal(high(r).length,0);
});
test('merging a fixed original URL with a replaced URL cannot retain the fixed destination',()=>{
 const r=run("const u=new URL('http://fixed.example.invalid/');if(req.body.flag)u.href=req.body.other;http.get(u);");
 assert.ok(!r.httpUses.some(u=>u.kind==='FIXED_DESTINATION'||u.kind==='ALLOWLISTED_DESTINATION'));
 if(!before)assert.equal(high(r).length,1);
});
