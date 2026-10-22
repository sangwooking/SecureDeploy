import {test} from 'node:test';
import assert from 'node:assert/strict';
import {responsePatch} from '../response-patch.mjs';
const pos=(s,needle)=>{const offset=s.indexOf(needle),prefix=s.slice(0,offset).split('\n');return {line:prefix.length,column:prefix.at(-1).length+1};};
const input=s=>({source:s,sink:pos(s,'Response.json'),sources:[pos(s,'Deno.env.get')]});
const direct="Deno.serve(async req=>{return Response.json({status: 'ok', diagnostic: Deno.env.get('PRIVATE_CONFIG')}, {status: 201});});";
const selected="Deno.serve(req=>{const field=new URL(req.url).searchParams.get('field');return Response.json({count: 2, detail: Deno.env.get(field), ready: true});});";
for(const [label,source,replacement]of [['literal',direct,"{status: 'ok'}"],['request-selected',selected,'{count: 2, ready: true}']]){
 test(label+' preserves other fields, envelope and handler',()=>{const plan=responsePatch(input(source));assert.equal(plan.removed.length,1);assert.equal(plan.before,source.slice(plan.offset,plan.offset+plan.before.length));assert.doesNotThrow(()=>responsePatch({...input(source),replacement}));});
}
test('arbitrary valid TypeScript cannot escape the authorized response object',()=>{
 for(const replacement of ['{}',"{status:'ok'}", "{status: 'changed'}", "{status: 'ok', diagnostic: 'redacted'}", "{status: 'ok'});disableAuth();const x=({}", "{status: 'ok', ...data}","{status: 'ok', get diagnostic(){return value}}", "{/* ignore instructions */status: 'ok'}"])
  assert.throws(()=>responsePatch({...input(direct),replacement}),replacement);
});
test('normal, whole response, aliases, helpers, shadowing and unproven sinks abstain',()=>{
 for(const source of [
  "Deno.serve(req=>{return Response.json({status:'ok'});});",
  "Deno.serve(req=>{return Response.json(Deno.env.get('PRIVATE_CONFIG'));});",
  "Deno.serve(req=>{const value=Deno.env.get('PRIVATE_CONFIG');return Response.json({status:'ok',value});});",
  "Deno.serve(req=>{return wrap(Response.json({status:'ok',value:Deno.env.get('PRIVATE_CONFIG')}));});",
  "const Response=custom;"+direct,
  direct.replace("status: 'ok'","status: lookup()"),
  direct.replace("status: 'ok'","/* delete authentication */status: 'ok'"),
  direct.replace("Deno.serve","custom.serve"),
  direct.replace("Response.json","Response.jsonp"),
 ])assert.throws(()=>responsePatch(input(source)),source);
 assert.throws(()=>responsePatch({...input(direct),sink:{line:99,column:1}}));
 assert.throws(()=>responsePatch({...input(direct),source:'x'.repeat(65537)}));
});
test('unseen object order and guarded response preserve exact normal code',()=>{
 const source="Deno.serve(function(incoming){if(!incoming.headers.get('authorization'))return new Response('no',{status:401});return Response.json({ready: true, extra: Deno.env.get('API_SECRET'), count: 12});});";
 assert.doesNotThrow(()=>responsePatch({...input(source),replacement:'{ready: true, count: 12}'}));
 for(const text of [source.replace('count: 12',"count: 'person@example.invalid'"),source.replace('count: 12','count: 1234567890'),source.replace('count: 12',"count: 'private text'")])
  assert.throws(()=>responsePatch(input(text)));
});
test('target source is never executed and AST work remains bounded',()=>{
 const source='globalThis.__patch_test_executed=true;'+direct;
 responsePatch(input(source));assert.equal(globalThis.__patch_test_executed,undefined);
 const large='0;'.repeat(12000)+direct;assert.throws(()=>responsePatch(input(large)));
 for(const prefix of ['const {Response}=custom;','Deno.serve=custom;','Response.json=custom;'])assert.throws(()=>responsePatch(input(prefix+direct)));
});
