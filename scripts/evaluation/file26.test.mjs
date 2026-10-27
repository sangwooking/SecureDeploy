import {test} from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {evaluate} from './file26.mjs';
test('frozen truth retains unsupported risky uploads as misses and normal guard as deferred',async()=>{
 const r=await evaluate(fileURLToPath(new URL('../../',import.meta.url)));
 assert.equal(r.rows.length,39);
 assert.deepEqual(r.summary.PATH,{TP:12,FN:6,TN:8,NORMAL_DEFERRED:1,NORMAL_NO_FS_SINK:1,UNKNOWN:5});
 assert.deepEqual(r.summary.UPLOAD_TYPE,{FN:1,UNKNOWN:5});
 assert.equal(r.rows.find(c=>c.id==='upload-executed').outcome,'FN');
 assert.equal(r.rows.find(c=>c.id==='path-relative-guard').outcome,'NORMAL_DEFERRED');
 assert.ok(r.rows.every(r=>!['FP','UNEXPECTED_CANDIDATE','FALSE_SAFE_OBSERVATION'].includes(r.outcome)));
});
