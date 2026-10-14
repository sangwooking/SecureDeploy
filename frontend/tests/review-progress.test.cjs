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

test('saved deployment assessments precede reference score and resolved entries have no remediation', () => {
  const result = fixture(), previous = JSON.stringify(result), html = render(result);
  assert.ok(html.indexOf('배포 전 수정 필요') < html.indexOf('룰 기반 참고 점수'));
  assert.ok(html.includes('해결된 문제 1'));
  assert.ok(html.includes('비교 확인 불가 1'));
  assert.ok(!html.includes('코드에서 인증정보 제거'));
  assert.ok(html.includes('이전 기술 정보 보기'));
  assert.equal(JSON.stringify(result), previous);
});
test('legacy and no-baseline are not shown as improvement or universally safe', () => {
  assert.ok(render({ ...fixture(), comparison: null }).includes('저장된 비교 결과가 없습니다'));
  const result = fixture(); result.comparison.assessmentBefore = null; result.comparison.status = 'NO_BASELINE';
  assert.ok(render(result).includes('평가 정보 없음'));
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
