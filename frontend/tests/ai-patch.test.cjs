const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {AiPatchPanel}=require('./load-component.cjs')('AiPatchPanel');
const base={workspace:{id:'w',identityStatus:'UNVERIFIED_REUPLOAD',revision:1},file:{id:'f',path:'application.properties'},content:{currentHash:'hash'},findings:[],dirty:false,disabled:false,onApplied(){}};
test('unverified ZIP and unsupported code stay manual, never a confirmed source association',()=>{
 const html=renderToStaticMarkup(React.createElement(AiPatchPanel,base));
 assert.ok(html.includes('ZIP 원본 미검증'));assert.ok(html.includes('생성은 파일을 바꾸지 않습니다'));assert.ok(!html.includes('동의한 코드로 AI 수정안 생성'));
});
test('unavailable Provider cannot masquerade as a generated patch',()=>{
 const html=renderToStaticMarkup(React.createElement(AiPatchPanel,{...base,workspace:{...base.workspace,identityStatus:'EXACT_GIT_COMMIT'}}));
 assert.ok(html.includes('AI 수정 Provider가 준비되지 않았습니다'));assert.ok(html.includes('수동 편집'));
});
test('new Express and logging evidence never advertises an unsupported automatic patch',()=>{
 for(const kind of ['EXPRESS_HTTP_RESPONSE','LOG_ARGUMENT']){
  const html=renderToStaticMarkup(React.createElement(AiPatchPanel,{...base,workspace:{...base.workspace,identityStatus:'EXACT_GIT_COMMIT'},file:{id:'f',path:'server.ts'},
   flowFindings:[{findingId:'new-flow',ruleId:'TS_SENSITIVE_DATA_EXPOSURE',location:{kind,line:1}}]}));
  assert.ok(!html.includes('자동 수정안 만들기'));assert.ok(!html.includes('AI 수정안 전송 범위 확인'));
 }
});
test('separate consent and acceptance gates retain uncertainty and never execute model code',()=>{
 const source=fs.readFileSync('src/components/AiPatchPanel.tsx','utf8');
 for(const value of ['!consented','!accepted','dirty','생성 취소·거절','STALE','해결 미검증','검토한 AI 수정안 적용'])assert.ok(source.includes(value),value);
 for(const denied of ['dangerouslySetInnerHTML','eval(','iframe','srcDoc'])assert.ok(!source.includes(denied));
 const api=fs.readFileSync('src/api/editingApi.ts','utf8');assert.ok(api.includes('consented: true'));assert.ok(api.includes('approved: true'));assert.ok(api.includes('currentHash: p.currentHash'));
});
test('Deno response patches require a structural identity and separate API impact acknowledgement',()=>{
 const source=fs.readFileSync('src/components/AiPatchPanel.tsx','utf8'),api=fs.readFileSync('src/api/editingApi.ts','utf8');
 for(const value of ['TS_SENSITIVE_DATA_EXPOSURE','HTTP_RESPONSE','compatibilityAccepted','API 호환성','객체 응답 코드','파일 전체가 아닙니다'])assert.ok(source.includes(value),value);
 assert.ok(api.includes('flowFindingId'));assert.ok(api.includes('responseContractAcknowledged: !!p.flowFindingId'));
});
test('deterministic generation is independent from AI availability and has no external consent step',()=>{
 const source=fs.readFileSync('src/components/AiPatchPanel.tsx','utf8'),api=fs.readFileSync('src/api/editingApi.ts','utf8');
 for(const value of ['DETERMINISTIC_FIX','AI_ASSISTED','MANUAL_REVIEW','자동 수정안 만들기','외부 AI 전송·비용 없음',"!deterministic&&selected.state === 'APPROVAL_REQUIRED'",'검토한 자동 수정안 적용'])assert.ok(source.includes(value),value);
 assert.ok(api.includes('/deterministic-patches'));assert.ok(api.includes('/fix-options'));
 assert.ok(source.includes('content.revision===workspace.revision'));assert.ok(source.includes('content.fileId===file.id'));
 assert.ok(!source.match(/!provider\?\.available\s*\?/));
});
