import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluate,cases} from './html_context.mjs';
import {classify} from '../../analyzers/typescript/url-context.mjs';
test('labelled controls retain danger, passive proof and uncertainty as distinct outcomes',()=>{
  assert.equal(new Set(cases.map(c=>c[0])).size,cases.length);
  const result=evaluate(classify);
  assert.deepEqual(result.totals,{TP:5,FP:0,FN:0,TN:6,UNKNOWN:7,incorrectExclusion:0});
  assert.ok(!JSON.stringify(result).includes('onerror='));
});
test('source relocation and submission order do not change HTML exclusions',()=>{
  for(const [, , ,files] of cases){
    const before=classify(files).files;
    const renamed=files.map((f,i)=>({...f,filePath:i?'messages/settings.ts':'src/views/Policy.tsx'})).reverse();
    const after=classify(renamed).files.reverse();
    assert.deepEqual(after.map(f=>f.excludedHtmlLines??[]),before.map(f=>f.excludedHtmlLines??[]));
  }
});
