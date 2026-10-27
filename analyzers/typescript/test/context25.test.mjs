import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';
import {classify} from '../url-context.mjs';
import {xss25Cases,ssrf25Cases,sqlBranch25} from './context25-cases.mjs';
for(const c of xss25Cases)test('HTML context25 '+c.id,()=>{
 const r=classify([{filePath:c.filePath,content:c.code}]).files[0];
 const excluded=r.excludedHtmlLines??[];
 if(c.truth==='RISK'||c.truth==='UNKNOWN')assert.equal(excluded.length,0);
 else if(!['xss-jsx-text','xss-text-content','xss-purified'].includes(c.id))assert.equal(excluded.length,1);
 if(c.id==='xss-purified')assert.equal(excluded.length,0,'Unimplemented sanitizer contract remains a review warning');
});
for(const c of ssrf25Cases)test('SSRF context25 '+c.id,()=>{
 const r=analyze(c.input),high=r.findings.filter(f=>f.ruleId==='TS_SSRF_INPUT_FLOW'&&f.confidence==='HIGH');
 const repaired30=c.id==='ssrf-guard-mutation';
 assert.equal(high.length,c.truth==='RISK'&&(!c.deferredRisk||repaired30)?1:0,JSON.stringify(r.httpUses));
 if(c.truth==='NORMAL'&&c.id!=='ssrf-fake'&&!c.knownGap)assert.ok(r.httpUses.some(u=>['FIXED_DESTINATION','ALLOWLISTED_DESTINATION'].includes(u.kind)));
 if(c.knownGap)assert.ok(r.httpUses.some(u=>u.kind==='ALLOWLISTED_DESTINATION'));
 if(c.truth==='UNKNOWN')assert.ok(!r.httpUses.some(u=>['FIXED_DESTINATION','ALLOWLISTED_DESTINATION'].includes(u.kind)));
 if(c.deferredRisk)assert.ok(!r.httpUses.some(u=>['FIXED_DESTINATION','ALLOWLISTED_DESTINATION'].includes(u.kind)),'Known misses must not acquire a safe destination fact');
});
test('inert conditional choices do not invalidate an unchanged SQL receiver',()=>{
 const r=analyze(sqlBranch25);assert.ok(r.nodeUses.some(u=>u.ruleId==='JS_SEQUELIZE_SQL_INPUT_FLOW'&&u.kind==='STATIC_OR_DATA_ONLY'));
 assert.ok(!r.findings.some(f=>f.ruleId==='JS_SEQUELIZE_SQL_INPUT_FLOW'));
});
test('dynamic choice mutations and parse budgets never prove passive HTML or a safe destination',()=>{
 const code="let html='<b>A</b>';html=location.hash;const V=()=> <div dangerouslySetInnerHTML={{__html:flag?html:'<b>B</b>'}}/>;";
 assert.deepEqual(classify([{filePath:'view.tsx',content:code}]).files[0].excludedHtmlLines,[]);
 const r=analyze(ssrf25Cases[0].input,{maxNodes:2,maxSteps:2});
 assert.ok(!r.httpUses.some(u=>['FIXED_DESTINATION','ALLOWLISTED_DESTINATION'].includes(u.kind)));
 assert.notEqual(r.status,'COMPLETED');
});
