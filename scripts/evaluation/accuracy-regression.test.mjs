import test from 'node:test';import assert from 'node:assert/strict';import{compareCase,compareCohort}from'./accuracy-regression.mjs';
const flow={ruleId:'RULE',confidence:'HIGH',source:{filePath:'a',line:1,kind:'SOURCE'},sink:{filePath:'a',line:4,kind:'SINK'},flow:[{line:1}]};
const row=(classification='FN',truth=true)=>({id:'frozen',truth,inputHash:'frozen-hash',classification,findings:classification==='TP'?[flow]:[],protections:[],coverage:{selected:2,parsed:2,entries:1,functions:2}});
test('FN to proven TP accepted without changing historical observations',()=>{const b=row(),copy=structuredClone(b),a=row('TP');assert.equal(compareCase(b,a).improved,true);assert.deepEqual(b,copy);});
test('lost files, parse, handlers or functions reject even new TP',()=>{for(const k of ['selected','parsed','entries','functions']){const a=row('TP');a.coverage[k]--;assert.equal(compareCase(row(),a).passed,false);}});
test('FN to UNKNOWN is abandonment, not improvement',()=>assert.equal(compareCase(row(),row('UNKNOWN')).passed,false));
test('FP hiding without protection is rejected',()=>assert.equal(compareCase(row('FP',false),row('TN',false)).passed,false));
test('safe case promotion and UNKNOWN promotion rejected',()=>{assert.equal(compareCase(row('TN',false),row('FP',false)).passed,false);assert.equal(compareCase(row('UNKNOWN',null),row('TP',null)).passed,false);});
test('new TP needs HIGH source/sink flow',()=>{const a=row('TP');a.findings=[{ruleId:'RULE'}];assert.equal(compareCase(row(),a).passed,false);});
test('changed original or oracle cannot be blessed',()=>{const a=row('TP');a.inputHash='changed';assert.equal(compareCase(row(),a).passed,false);a.inputHash='frozen-hash';a.truth=false;assert.equal(compareCase(row(),a).passed,false);});
test('engine/finding ID change alone cannot erase established flow',()=>{const b=row('TP'),a=row('TP');a.findings=[{...flow,id:'new',engine:'v60'}];assert.equal(compareCase(b,a).passed,true);a.findings=[];assert.equal(compareCase(b,a).passed,false);});
test('case removal and duplication fail closed',()=>{assert.throws(()=>compareCohort([row()],[]));assert.throws(()=>compareCohort([row(),row()],[row(),row()]));});

test('evidence-backed review on unknown stays UNKNOWN, never counted TP',()=>{const b=row('UNKNOWN',null),a=row('UNKNOWN',null);a.unexpectedUnknownPromotion=true;a.findings=[{...flow,disposition:'REVIEW_REQUIRED'}];assert.equal(compareCase(b,a).passed,true);assert.equal(compareCase(b,a).improved,false);a.findings[0].disposition='CONFIRMED';assert.equal(compareCase(b,a).passed,false);});

test('normal case cannot disappear into UNKNOWN and binding proofs cannot be discarded',()=>{assert.equal(compareCase(row('TN',false),row('UNKNOWN',false)).passed,false);const b=row('TN',false),a=row('TN',false);b.protections=[{kind:'VALUE_BINDING',filePath:'a',line:4},{kind:'NUMERIC_GUARD',filePath:'a',line:1}];a.protections=[b.protections[1]];assert.equal(compareCase(b,a).passed,false);});
