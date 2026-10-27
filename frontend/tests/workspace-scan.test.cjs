const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {WorkspaceScanPanel}=require('./load-component.cjs')('WorkspaceScanPanel');
test('workspace rescan explicitly binds revision, STANDARD and external lookup consent',()=>{
 const html=renderToStaticMarkup(React.createElement(WorkspaceScanPanel,{workspace:{id:'w',revision:4,changedFileIds:['f'],identityStatus:'EXACT_GIT_COMMIT'},original:{reviewId:1},disabled:false}));
 for(const text of ['수정본 버전 4','STANDARD','OSV','EPSS/KEV','유료 AI는 호출하지 않습니다'])assert.ok(html.includes(text),text);
 assert.match(html,/<button[^>]*disabled/);
});
test('unverified ZIP does not claim old findings were fixed',()=>{
 const html=renderToStaticMarkup(React.createElement(WorkspaceScanPanel,{workspace:{id:'w',revision:1,changedFileIds:[],identityStatus:'UNVERIFIED_REUPLOAD'},original:{reviewId:1},disabled:false}));
 assert.ok(html.includes('별도 프로젝트'));assert.ok(html.includes('해결 처리하지 않습니다'));
});
test('rescan remains separate from editor busy state and never executes source HTML',()=>{
 const source=fs.readFileSync('src/components/WorkspaceScanPanel.tsx','utf8');
 for(const value of ['scan.revision !== workspace.revision','최신 수정본은 아직 재검사되지 않았습니다','loadWorkspaceScan','fetchReviewDetail','NOT_COMPARED'])assert.ok(source.includes(value),value);
 for(const denied of ['dangerouslySetInnerHTML','eval(','iframe','srcDoc'])assert.ok(!source.includes(denied));
 const api=fs.readFileSync('src/api/editingApi.ts','utf8');assert.ok(api.includes('externalLookupAcknowledged: true'));assert.ok(api.includes('changedFileIds: w.changedFileIds'));
});
