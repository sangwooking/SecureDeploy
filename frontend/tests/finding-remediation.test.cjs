const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { FindingRemediation, RemediationNotice } = require('./load-component.cjs')('FindingRemediation');
const render = (component, props) => renderToStaticMarkup(React.createElement(component, props));
const finding = { findingId: 'code:42', priority: 'BLOCKING' };
const item = { findingId: 'code:42', provider: 'template', model: null, promptVersion: 'remediation-v1',
  generatedAt: '2026-10-09T00:00:00Z', generationStatus: 'TEMPLATE', advice: {
    summary: 'credential rotation', whyItMatters: 'exposure', recommendedAction: 'rotate',
    codeExample: '<script>not executable</script>', configurationExample: 'password: ${DB_PASSWORD}',
    verificationSteps: ['rescan'], caution: 'review assumptions', remediationConfidence: 'MEDIUM',
  } };
test('guide uses exact finding identity and escapes model output', () => {
  const html = render(FindingRemediation, { finding, snapshot: { findings: [item] } });
  for (const text of ['수정·확인 가이드', '무엇을 수정해야 하나요?', '수정 후 무엇을 확인하나요?', '탐지 신뢰도와 별개', '&lt;script&gt;', '${DB_PASSWORD}']) assert.ok(html.includes(text));
  assert.ok(!html.includes('<script>'));
  const other = render(FindingRemediation, { finding: { ...finding, findingId: 'code:43' }, snapshot: { findings: [item] } });
  assert.ok(other.includes('기본 안내'));
  assert.ok(!other.includes('credential rotation'));
  assert.ok(!other.includes('${DB_PASSWORD}'));
});
test('legacy history and unavailable generation never claim safety', () => {
  assert.ok(render(RemediationNotice, { snapshot: null }).includes('저장된 해결 방법이 없습니다'));
  const html = render(FindingRemediation, { finding, snapshot: { findings: [{ ...item, advice: null, generationStatus: 'UNAVAILABLE' }] } });
  assert.ok(html.includes('생성 불가'));
  assert.ok(!html.includes('SAFE'));
});
test('review-needed guide retains verification and template provenance', () => {
  const html = render(FindingRemediation, { finding: { ...finding, priority: 'REVIEW_REQUIRED' }, snapshot: { findings: [{ ...item,
    advice: { ...item.advice, summary: '실제 사용 여부 확인', codeExample: null, configurationExample: null, remediationConfidence: 'LOW' } }] } });
  assert.ok(html.includes('실제 사용 여부 확인'));
  assert.ok(html.includes('템플릿 가이드'));
  assert.ok(!html.includes('코드 예시'));
  assert.ok(html.includes('배포 판단은 변경하지 않습니다'));
});
test('cost and omitted findings remain explicit', () => {
  const html = render(RemediationNotice, { snapshot: { notices: ['template fallback'], omittedFindingCount: 4, usage: { provider: 'OPENAI', totalTokens: 200 } } });
  assert.ok(html.includes('4개 문제'));
  assert.ok(html.includes('200 tokens'));
  assert.ok(html.includes('비용 추정 미산정'));
});
