import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../analyzer.mjs';

// Separate composed evaluation cases; not an externally authored benchmark.
const cases = [
  ['body/alias/Request', 'RISK', 'const body=await request.json(); const x=body.callback; return fetch(new Request(x));'],
  ['header/host', 'RISK', 'const host=request.headers.get("host-choice"); return fetch("https://"+host+"/status");'],
  ['route/local', 'RISK', 'return forward(params.destination);', 'function forward(u){return fetch(u);}'],
  ['assignment/both paths', 'RISK', 'let u=q; if(flag) u="https://static.example.invalid/"; return fetch(u);'],
  ['parameter snapshots', 'RISK', 'let u=q; return forward(u,u="https://static.example.invalid/");', 'function forward(a,b){return fetch(a);}'],
  ['URL/href', 'RISK', 'const u=new URL(q); return fetch(u.href);'],
  ['network-relative base', 'RISK', 'return fetch(new URL("//"+q,"https://static.example.invalid/"));'],
  ['fixed/payload', 'NORMAL', 'return fetch(new Request("https://static.example.invalid/",{method:"POST",body:q}));'],
  ['fixed/path', 'NORMAL', 'return fetch("https://static.example.invalid/files/"+q);'],
  ['fixed/unknown query', 'NORMAL', 'return fetch("https://static.example.invalid/?q="+unmodeled(q));'],
  ['fixed/fragment', 'NORMAL', 'return fetch(`https://static.example.invalid/#${q}`);'],
  ['branch overwrite', 'NORMAL', 'let u=q; if(flag) u="https://a.example.invalid/"; else u="https://b.example.invalid/"; return fetch(u);'],
  ['literal includes and protocol', 'NORMAL', 'const u=new URL(q); if(u.protocol!=="https:") return; if(!["a.example.invalid","b.example.invalid"].includes(u.hostname)) return; return fetch(u);'],
  ['conjunctive allowlist', 'NORMAL', 'const u=new URL(q); if(u.protocol==="https:" && u.hostname==="a.example.invalid") return fetch(u);'],
  ['incoming route host not proven', 'UNKNOWN', 'return fetch(request.url);'],
  ['URL component alone not complete address', 'UNKNOWN', 'return fetch(new URL(q).hostname);'],
  ['opaque wrapper', 'UNKNOWN', 'return fetch(customUrlBuilder(q));'],
  ['unknown authorization/validator', 'UNKNOWN', 'if (!isAllowed(q)) return; return fetch(q);'],
  ['only hostname checked', 'UNKNOWN', 'const u=new URL(q); if(u.hostname!=="a.example.invalid") return; return fetch(u);'],
  ['callee branch mutation', 'UNKNOWN', 'const u=new URL("https://a.example.invalid/"); rewrite(u,q); return fetch(u);', 'function rewrite(u,q){if(flag) u.hostname=q;}'],
  ['guard then mutation alias', 'UNKNOWN', 'const u=new URL(q); if(u.protocol!=="https:"||u.hostname!=="a.example.invalid") return; const alias=u; alias.href=q; return fetch(u);'],
];
test('SSRF composed evaluation separates destination control, normal initial destinations, and abstention', t => {
  const counts={truePositive:0,falsePositive:0,falseNegative:0,trueNegative:0,expectedUnknown:0,abstained:0,riskAbstained:0,incorrectCertainty:0};
  const mismatches=[];
  for (const [id,label,code,helpers=''] of cases) {
    const r=analyze({files:[{filePath:'functions/proxy.ts',content:`${helpers} export async function onRequest({request,params}){const q=new URL(request.url).searchParams.get('q'); ${code}}`}]});
    const high=r.findings.some(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH');
    const unresolved=!r.httpUses.length||r.httpUses.some(u=>u.kind==='UNRESOLVED_DESTINATION');
    if(label==='RISK') { if(high) counts.truePositive++; else { if(unresolved) counts.riskAbstained++; else counts.falseNegative++; mismatches.push(id); } }
    else if(label==='NORMAL') { if(high) {counts.falsePositive++;mismatches.push(id);} else if(!unresolved) counts.trueNegative++; else {counts.abstained++;mismatches.push(id);} }
    else {counts.expectedUnknown++; if(!high&&unresolved) counts.abstained++; else {counts.incorrectCertainty++;mismatches.push(id);} }
  }
  t.diagnostic(JSON.stringify(counts)); assert.deepEqual(mismatches,[]);
});

test('URL mutations never erase SQL provenance through query/path reads or branch merges', () => {
  for(const body of [
    'u.searchParams.set("q",q); return env.DB.prepare(u.searchParams.get("q")).all();',
    'u.pathname=q; return env.DB.prepare(u.pathname).all();',
    'if(flag) u.pathname=q; return env.DB.prepare(u.pathname).all();',
    'if(flag) u.searchParams.set("q",q); return env.DB.prepare(u.searchParams.get("q")).all();',
  ]) {
    const r=analyze({files:[{filePath:'worker.ts',content:`export default {fetch(request,env){const q=new URL(request.url).searchParams.get('q'); const u=new URL('https://a.example.invalid/'); ${body}}}`}]});
    assert.equal(r.sqlUses[0].kind,'INPUT_IN_QUERY',body);
  }
});
test('SSRF respects step, depth, trace and output limits without certifying incomplete flow', () => {
  const content='function f(x){return f(x)} export default {fetch(request){return fetch(f(request.headers.get("x")));}}';
  const r=analyze({files:[{filePath:'worker.ts',content}]});
  assert.equal(r.httpUses[0].kind,'UNRESOLVED_DESTINATION');
  assert.ok(r.files[0].limitations.includes('CALL_DEPTH_EXCEEDED'));
  const limited=analyze({files:[{filePath:'worker.ts',content}]},{maxSteps:2});
  assert.equal(limited.status,'PARTIAL');
  assert.equal(limited.findings.length,0);
  const many=analyze({files:[{filePath:'worker.ts',content:`export default {fetch(request){const u=request.headers.get('x'); ${'fetch(u);'.repeat(210)}}}`} ]});
  assert.ok(many.httpUses.length<=200);
  assert.ok(many.files[0].limitations.includes('RESULT_LIMIT_EXCEEDED'));
});
