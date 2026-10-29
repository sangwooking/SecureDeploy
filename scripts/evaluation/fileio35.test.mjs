import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateFileIo} from './fileio35.mjs';
test('fixed file IO controls separate conditional completion from unknown and blocked flows',()=>{
 const rows=evaluateFileIo();assert.equal(rows.length,23);
 for(const r of rows){assert.equal(r.high,r.expected==='HIGH'?1:0,r.id);assert.equal(r.medium,r.expected==='CONDITIONAL'?1:0,r.id);}
 assert.equal(rows.filter(r=>r.expected==='UNKNOWN').length,11);
});
