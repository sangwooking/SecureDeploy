import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../analyzer.mjs';

const start = 'let target = new URL(request.url).searchParams.get("url");';
export const run = (body, functions = '', options = {}) => analyze({ files: [{ filePath: 'worker.ts',
  content: `${functions} export default { async fetch(request,env) { ${start} ${body} } };` }] }, options);
const cases = [
  ['query destination', 'return fetch(target);', 'INPUT_IN_DESTINATION'],
  ['body destination', 'const body=await request.json(); return fetch(body.url);', 'INPUT_IN_DESTINATION'],
  ['header destination', 'return fetch(request.headers.get("x-target"));', 'INPUT_IN_DESTINATION'],
  ['host template', 'return fetch(`https://${target}/items`);', 'INPUT_IN_DESTINATION'],
  ['incomplete authority allows userinfo override', 'return fetch("https://api.example.invalid" + target);', 'INPUT_IN_DESTINATION'],
  ['URL base does not constrain absolute input', 'return fetch(new URL(target,"https://api.example.invalid/"));', 'INPUT_IN_DESTINATION'],
  ['Request retains destination', 'const r=new Request(target,{method:"GET"}); return fetch(r);', 'INPUT_IN_DESTINATION'],
  ['fixed URL query', 'return fetch("https://api.example.invalid/search?q=" + target);', 'FIXED_DESTINATION'],
  ['encoded query', 'return fetch(`https://api.example.invalid/search?q=${encodeURIComponent(target)}`);', 'FIXED_DESTINATION'],
  ['fixed URL body', 'return fetch("https://api.example.invalid/",{method:"POST",body:target});', 'FIXED_DESTINATION'],
  ['fixed URL and query setter', 'const u=new URL("https://api.example.invalid/"); u.searchParams.set("q",target); return fetch(u);', 'FIXED_DESTINATION'],
  ['fixed URL pathname setter', 'const u=new URL("https://api.example.invalid/"); u.pathname=target; return fetch(u);', 'FIXED_DESTINATION'],
  ['relative path with fixed first segment', 'return fetch(new URL("/items/"+target,"https://api.example.invalid/"));', 'FIXED_DESTINATION'],
  ['slash alone is not an origin constraint', 'return fetch(new URL("/"+target,"https://api.example.invalid/"));', 'INPUT_IN_DESTINATION'],
  ['fixed choices', 'const u=target ? "https://one.example.invalid/" : "https://two.example.invalid/"; return fetch(u);', 'FIXED_DESTINATION'],
  ['exact parsed protocol and hostname', 'const u=new URL(target); if(u.protocol!=="https:" || u.hostname!=="api.example.invalid") return; return fetch(u);', 'ALLOWLISTED_DESTINATION'],
  ['checks do not validate original string after reassignment', 'const u=new URL(target); if(u.protocol!=="https:" || u.hostname!=="api.example.invalid") return; target=await request.text(); return fetch(target);', 'INPUT_IN_DESTINATION'],
  ['raw startsWith is not proven safety', 'if(!target.startsWith("https://api.example.invalid")) return; return fetch(target);', 'UNRESOLVED_DESTINATION'],
  ['unknown transform', 'return fetch(normalize(target));', 'UNRESOLVED_DESTINATION'],
  ['URL mutated through alias', 'const u=new URL("https://api.example.invalid/"); const alias=u; alias.hostname=target; return fetch(u);', 'UNRESOLVED_DESTINATION'],
  ['unknown wrapper can mutate URL', 'const u=new URL("https://api.example.invalid/"); rewrite(u,target); return fetch(u);', 'UNRESOLVED_DESTINATION'],
  ['left value before overwrite', 'return fetch(target + (target=""));', 'INPUT_IN_DESTINATION'],
  ['overwrite before right value', 'return fetch((target="https://api.example.invalid/") + target);', 'FIXED_DESTINATION'],
  ['template assignment order', 'return fetch(`${target}${target=""}`);', 'INPUT_IN_DESTINATION'],
  ['unsupported execution path', 'for (const item of items) { await fetch(target); }', 'UNRESOLVED_DESTINATION'],
  ['URL component template is not a complete destination', 'return fetch(`${new URL(target).pathname}`);', 'UNRESOLVED_DESTINATION'],
  ['encoding alone does not preserve arbitrary absolute URL', 'return fetch(`${encodeURIComponent(target)}`);', 'UNRESOLVED_DESTINATION'],
  ['header overwritten is not confirmed attacker control', 'request.headers.set("x-target","https://fixed.example.invalid/"); return fetch(request.headers.get("x-target"));', 'UNRESOLVED_DESTINATION'],
  ['query overwritten is not confirmed attacker control', 'const u=new URL(request.url); u.searchParams.set("url","https://fixed.example.invalid/"); return fetch(u.searchParams.get("url"));', 'UNRESOLVED_DESTINATION'],
];
for (const [name, body, expected] of cases) test(`SSRF: ${name}`, () => {
  const r=run(body);
  assert.equal(r.httpUses?.length, 1);
  assert.equal(r.httpUses[0].kind, expected);
  const findings=r.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW');
  assert.equal(findings.some(f=>f.confidence==='HIGH'), expected==='INPUT_IN_DESTINATION');
  assert.ok(r.httpUses[0].limitations.includes('REDIRECT_DNS_REACHABILITY_NOT_VERIFIED'));
});
test('SSRF: only reachable calls of global fetch are request sinks', () => {
  for (const body of ['new Request(target);', 'if(false) fetch(target);', 'const fetch=(x)=>x; fetch(target);', 'env.service.fetch(target);'])
    assert.equal(run(body).httpUses?.length,0,body);
});
test('SSRF: local and relative imported functions preserve destination flow', () => {
  assert.equal(run('return send(target);','function send(url){return fetch(new Request(url));}').httpUses?.[0].kind,'INPUT_IN_DESTINATION');
  const r=analyze({files:[
    {filePath:'functions/proxy.ts',content:'import {send} from "../send"; export function onRequest({params}) {return send(params.target);}'},
    {filePath:'send.ts',content:'export function send(url) {return fetch(url);}'}]});
  assert.equal(r.httpUses?.[0].kind,'INPUT_IN_DESTINATION');
  assert.equal(r.findings[0].source.kind,'ROUTE_PARAMETER');
});
test('SSRF: source text, literal destinations and header names are not serialized', () => {
  const r=run('return fetch("https://"+request.headers.get("synthetic-private-header")+"/private-path-marker");');
  assert.equal(r.httpUses?.length,1);
  assert.doesNotMatch(JSON.stringify(r),/synthetic-private-header|private-path-marker/);
});
