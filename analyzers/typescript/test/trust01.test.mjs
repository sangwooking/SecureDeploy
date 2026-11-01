import{test}from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import{analyze}from'../analyzer.mjs';
const cases=JSON.parse(fs.readFileSync(new URL('../../../scripts/evaluation/trust01-inputs.json',import.meta.url))).cases;
test('direct native result, alias and projection reach response without becoming request injection taint',()=>{for(const id of['params','session','projection']){const r=analyze(cases.find(c=>c.id===id).input);assert.ok(r.nodeUses.some(n=>n.kind==='MONGO_RESULT_HTTP_RESPONSE_OBSERVED'),id);assert.equal(r.findings.length,0);}});
test('no response, error-only success branch and dynamic receiver never claim result delivery',()=>{for(const id of['no_response','error_only','dynamic']){const r=analyze(cases.find(c=>c.id===id).input);assert.ok(!r.nodeUses.some(n=>n.kind==='MONGO_RESULT_HTTP_RESPONSE_OBSERVED'),id);}});
test('authorization policy remains unknown even for a result visibly used in HTTP',()=>{for(const id of['public','admin','comparison']){const r=analyze(cases.find(c=>c.id===id).input);assert.equal(r.findings.filter(f=>/IDOR|AUTHORIZATION/.test(f.ruleId)).length,0);assert.ok(r.authorizationContexts.every(c=>c.conclusion==='NOT_VERIFIED'));}});
test('postimplementation nested callback regression keeps the actual value and rejects unrelated projection',()=>{
 for(const [value,expected]of[['row',1],["{label:'other'}",0]]){
  const input=structuredClone(cases[0].input),src=input.files[0].content;
  input.files[0].content="function relay(value,done){done(value);}"+src.replace('res.json(row);',`relay(${value},function(payload){res.json(payload);});`);
  const r=analyze(input);assert.equal(r.nodeUses.filter(n=>n.kind==='MONGO_RESULT_HTTP_RESPONSE_OBSERVED').length,expected);
 }
});
