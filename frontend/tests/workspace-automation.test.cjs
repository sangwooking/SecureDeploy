const {test}=require('node:test'),assert=require('node:assert/strict'),React=require('react'),{renderToStaticMarkup}=require('react-dom/server');
const {WorkspaceAutomationPanels}=require('./load-component.cjs')('WorkspaceAutomationPanels');
test('initial review and generation panels do not send code, run npm, or apply without separate steps',()=>{
 const props={workspace:{id:'fixture',revision:1},disabled:false,adviceId:'verified-advice',onApplied:async()=>{throw Error('Not expected during render');}};const before=JSON.stringify(props.workspace);const html=renderToStaticMarkup(React.createElement(WorkspaceAutomationPanels,props));
 assert.ok(html.includes('추가 검토 전송 범위 확인'));assert.ok(html.includes('npm 파일 생성 범위 확인'));assert.ok(!html.includes('승인한 두 파일 적용'));assert.ok(!html.includes('동의한 문맥 추가 검토'));assert.equal(JSON.stringify(props.workspace),before);
});
test('manual workspaces do not gain an unrelated dependency proposal',()=>{
 const html=renderToStaticMarkup(React.createElement(WorkspaceAutomationPanels,{workspace:{id:'fixture',revision:1},disabled:false,onApplied:async()=>{}}));assert.ok(!html.includes('npm 파일 생성 범위 확인'));assert.ok(html.includes('다른 UNKNOWN·전체 프로젝트의 검토를 의미하지 않습니다'));
});
