const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const fixture = require('./progress-fixture.cjs');
const { ReviewProgressPanel } = load('ReviewProgressPanel');
const { RescanForm } = load('RescanForm');
const { codeExplanation } = load('reviewPresentation');
const render = result => renderToStaticMarkup(React.createElement(ReviewProgressPanel, { result }));
test('workspace comparison identifies a revision, not a missing or newly pushed Git commit',()=>{
  const result=fixture();result.comparison.workspaceScan={revision:2,originalReviewId:1,baselineVerified:true,sourceRevision:'a'.repeat(40),inputHash:'b'.repeat(64),analyzerVersion:'fixture',files:[]};
  const before=JSON.stringify(result),html=render(result);
  assert.ok(html.includes('수정본은 새 GitHub commit이 아닙니다'));assert.ok(html.includes('원본 버전과 수정 revision·입력 해시'));
  assert.ok(!html.includes('현재 commit 정보 없음'));assert.ok(html.includes('NOT_COMPARED'));assert.equal(JSON.stringify(result),before);
});
test('approved deterministic edits are not mislabeled as AI output',()=>{
 const result=fixture();result.comparison.workspaceScan={revision:2,originalReviewId:1,baselineVerified:true,sourceRevision:'a'.repeat(40),inputHash:'b'.repeat(64),analyzerVersion:'fixture',files:[
  {fileId:'one',path:'index.ts',changed:true,changeOrigin:'DETERMINISTIC_APPROVED',originalHash:'c'.repeat(64),currentHash:'d'.repeat(64)},
  {fileId:'two',path:'other.ts',changed:true,changeOrigin:'MANUAL_AFTER_DETERMINISTIC',originalHash:'c'.repeat(64),currentHash:'d'.repeat(64)}]};
 const html=render(result);assert.ok(html.includes('승인된 자동 수정'));assert.ok(html.includes('자동 수정 적용 후 수동 변경'));assert.ok(!html.includes('승인된 AI 수정'));
});

test('saved deployment assessments precede reference score and resolved entries have no remediation', () => {
  const result = fixture(), previous = JSON.stringify(result), html = render(result);
  assert.ok(html.indexOf('배포 전 수정 필요') < html.indexOf('규칙 기반 참고 점수'));
  assert.match(html,/해결된 문제 <strong>1<\/strong>/);
  assert.match(html,/비교 확인 불가 <strong>1<\/strong>/);
  assert.ok(!html.includes('코드에서 인증정보 제거'));
  assert.ok(html.includes('이전 기술 정보 보기'));
  assert.equal(JSON.stringify(result), previous);
});
test('legacy and no-baseline are not shown as improvement or universally safe', () => {
  assert.ok(render({ ...fixture(), comparison: null }).includes('비교할 이전 검사가 없어요'));
  const result = fixture(); result.comparison.assessmentBefore = null; result.comparison.status = 'NO_BASELINE';
  assert.ok(render(result).includes('비교할 이전 검사가 없어요'));
  assert.ok(!render(result).includes('보안 상태가 개선되었습니다'));
});
test('AI disappearance is separate from deterministic resolution', () => {
  const html = render(fixture());
  assert.ok(html.includes('이번 AI 검토에서 다시 관찰되지 않음'));
  assert.ok(html.includes('AI가 다시 제안하지 않았다는 사실만으로 해결되었다고 판단하지 않습니다'));
});
test('rescan requests a new zip or displays saved github url with explicit confirmation', () => {
  const result = fixture();
  const props = { onScan() {}, onCancel() {} };
  assert.ok(renderToStaticMarkup(React.createElement(RescanForm, { result, ...props })).includes('수정된 프로젝트 ZIP'));
  result.sourceType = 'GITHUB'; result.repositoryUrl = 'https://github.com/fixture/progress';
  const html = renderToStaticMarkup(React.createElement(RescanForm, { result, ...props }));
  assert.ok(html.includes(result.repositoryUrl)); assert.ok(html.includes('대상 확인 후 다시 검사'));
  assert.ok(!html.includes('type="file"')); assert.match(html, /<option[^>]*value="STANDARD"[^>]*selected=""/);
});
test('infrastructure copy is understandable but preserves a technical location', () => {
  for (const ruleId of ['DOCKER_SECRET_ENV', 'K8S_SECRET_PLAIN_TEXT', 'DOCKER_ROOT_USER']) {
    const v = { ...fixture().vulnerabilities[0], ruleId, message: 'Original technical message' };
    assert.ok(codeExplanation(v).location); assert.notEqual(codeExplanation(v).title, v.message);
  }
});
test('engine-only changes show matched original IDs without zero cards or remediation claims',()=>{
 const result=fixture();result.comparison.counts={RESOLVED:0,NEW:0,REMAINING:0,CHANGED:0,UNAVAILABLE:0};result.comparison.findings=[];
 result.comparison.basis={sourceState:'SAME_ANALYZED_INPUT',engineState:'CHANGED',message:'분석 엔진이 변경됐습니다.',enginesBefore:{typescript:'ts-server-v52'},enginesAfter:{typescript:'ts-server-v53'},limitations:[],flowChanges:[{status:'OBSERVED_BOTH',ruleId:'JS_EVAL_INPUT_FLOW',beforeId:'old-id',afterId:'new-id',before:null,after:null,note:'ID 변경을 해결로 처리하지 않습니다.'}]};
 const before=JSON.stringify(result),html=render(result);for(const phrase of ['수집한 분석 입력 내용 동일','분석 엔진: 변경됨','두 검사에서 같은 코드 근거 관찰','old-id','new-id'])assert.ok(html.includes(phrase),phrase);
 assert.ok(!html.includes('<strong>0</strong>'));assert.ok(!html.includes('보안 상태가 개선되었습니다'));assert.equal(JSON.stringify(result),before);
});
test('code-and-engine changes keep unknown flow comparisons outside resolved and new totals',()=>{
 const result=fixture();result.comparison.counts={RESOLVED:0,NEW:0,REMAINING:0,CHANGED:0,UNAVAILABLE:0};result.comparison.findings=[];
 result.comparison.basis={sourceState:'CHANGED_ANALYZED_INPUT',engineState:'CHANGED',message:'코드 수정과 엔진 변경의 영향을 분리하지 못했습니다.',enginesBefore:{},enginesAfter:{},limitations:[],flowChanges:[{status:'UNAVAILABLE',ruleId:'TS_SENSITIVE_DATA_EXPOSURE',beforeId:'old',afterId:null,before:null,after:null,note:'해결로 집계하지 않습니다.'}]};
 const html=render(result);assert.ok(html.includes('수집한 분석 입력 내용 변경'));assert.ok(html.includes('흐름 비교 확인 불가'));assert.ok(!html.includes('<strong>0</strong>'));
});
test('unverified historical counts remain in technical archive and are not confirmed remediation cards',()=>{const result=fixture();delete result.comparison.basis;const html=render(result);assert.ok(html.includes('과거 비교의 코드·엔진 근거가 부족해요'));assert.ok(html.includes('archivedCounts'));assert.ok(!html.includes('progress-filters'));assert.ok(!html.includes('해결된 문제 <strong>'));});
