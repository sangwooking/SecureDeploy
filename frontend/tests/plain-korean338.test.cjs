const {test}=require('node:test');
const assert=require('node:assert/strict');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const load=require('./load-component.cjs');
const {ReviewResultWorkspace}=load('ReviewResultWorkspace');
const {inspectionLabel}=load('uiLanguage');
const {parseWorkspaceRoute}=load('workspaceRoute');
const fixture=require('./result-fixture.cjs');
const render=(result,view)=>renderToStaticMarkup(React.createElement(ReviewResultWorkspace,{result,view,onViewChange(){},statusActions:{updatingId:null,comments:{},onComment(){},onStatus(){}},reportActions:null,progress:null}));
test('plain labels never rewrite persisted enums or turn unknown into safe',()=>{
  assert.equal(inspectionLabel('UNKNOWN'),'판단할 정보가 부족해요');
  assert.equal(inspectionLabel('NOT_COMPARED'),'이전 검사와 비교하지 못했어요');
  assert.equal(inspectionLabel('FUTURE_STATE'),'상세 검사 기록을 확인해 주세요');
});
test('actionable first issue retains backend priority and precedes reference facts',()=>{
  const r=fixture(),before=JSON.stringify(r),html=render(r,'SUMMARY');
  assert.ok(html.indexOf('가장 먼저 확인할 문제')<html.indexOf('검사 규칙 기준 참고 점수'));
  assert.ok(html.indexOf('data-priority="BLOCKING"')<html.indexOf('data-priority="SHOULD_FIX"'));
  assert.ok(html.includes(r.riskAssessment.codeFindings[0].sourceFiles[0]));
  assert.equal(JSON.stringify(r),before);
});
test('library view is deep-linkable without changing existing view routes',()=>{
  assert.equal(parseWorkspaceRoute('#/projects/7/findings?view=LIBRARIES').view,'LIBRARIES');
  assert.equal(parseWorkspaceRoute('#/projects/7/findings?view=TECHNICAL').view,'TECHNICAL');
  assert.equal(parseWorkspaceRoute('#/projects/7/findings?view=untrusted').view,'SUMMARY');
  const r=fixture(),before=JSON.stringify(r),html=render(r,'LIBRARIES');
  assert.ok(html.includes('외부 라이브러리 보안'));
  assert.ok(html.includes(r.sca.dependencyVulnerabilities[0].packageName));
  assert.ok(html.includes('고유 취약점 수나 수정 작업 수와 달라요'));
  assert.equal(JSON.stringify(r),before);
});
test('failed or disabled library checks never claim that a lookup was completed',()=>{
  for(const status of ['DISABLED','UNAVAILABLE','PARTIAL']){
    const r=fixture();r.sca.status=status;const html=render(r,'LIBRARIES');
    assert.ok(!html.includes('보안 문제가 있는 항목을 확인했어요'));
    assert.ok(html.includes(inspectionLabel(status)));
  }
});
