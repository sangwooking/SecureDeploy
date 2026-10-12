const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { SemanticReviewSection } = require('./load-component.cjs')('SemanticReviewSection');
const render = snapshot => renderToStaticMarkup(React.createElement(SemanticReviewSection, { snapshot }));
const candidate = { candidateId: 'fixture-candidate', candidateType: 'IDOR', title: '<script>fixture</script>',
  semanticAnalysisConfidence: 'MEDIUM', reason: '소유권 확인 필요',
  evidence: [{ filePath: 'UserController.java', startLine: 7, endLine: 12, functionName: 'findUser(long)', evidenceDescription: '확인 필요' }],
  verificationSteps: ['공통 authorization 확인'], relatedExistingFindingIds: [] };
const snapshot = { scanMode: 'AI_ENHANCED', semanticReviewStatus: 'COMPLETED', candidates: [candidate], existingFindingEvidence: [],
  slices: [], semanticSlicesAnalyzed: 1, omittedSlices: 2, rejectedCandidates: 0, deduplicatedCandidates: 0,
  provider: 'openai', model: 'fixture-model', promptVersion: 'semantic-v1', generatedAt: '2026-10-12T00:00:00Z',
  requestCount: 1, usage: { totalTokens: 150 }, notices: ['fixture notice'] };
test('semantic candidates stay separate and render escaped grounded evidence', () => {
  const html = render(snapshot);
  for (const value of ['AI 보안 추가 검토', '확정 취약점이 아닙니다', '1개 항목 확인 필요', 'REVIEW REQUIRED',
    '의미 분석 신뢰도: MEDIUM', 'UserController.java:7-12', '공통 authorization 확인', '&lt;script&gt;', '150 tokens']) assert.ok(html.includes(value), value);
  assert.ok(!html.includes('<script>'));
});
test('legacy, standard, failure and empty completion never imply safe', () => {
  assert.ok(render(null).includes('저장된 Semantic Review가 없습니다'));
  for (const status of ['NOT_REQUESTED', 'FAILED', 'UNAVAILABLE', 'REJECTED', 'NO_SUPPORTED_CONTEXT', 'COMPLETED']) {
    const html=render({ ...snapshot, semanticReviewStatus: status, candidates: [] });
    assert.ok(html.includes('안전을 의미하지 않습니다'));
    assert.ok(!html.includes('READY TO DEPLOY'));
  }
});
test('existing findings are additional evidence not extra candidate count', () => {
  const html=render({ ...snapshot, candidates: [], existingFindingEvidence: [{ ...candidate, relatedExistingFindingIds: ['code:9'] }] });
  assert.ok(html.includes('별도 후보 수 제외'));
  assert.ok(html.includes('code:9'));
  assert.ok(!html.includes('1개 항목 확인 필요'));
});
test('coverage and partial validation remain visible', () => {
  const html=render({ ...snapshot, semanticReviewStatus: 'PARTIAL', rejectedCandidates: 2, deduplicatedCandidates: 1 });
  for (const value of ['일부 후보 검증 실패', '거부 후보 2개', '중복 제거 1개', '생략 2개', '요청 1회']) assert.ok(html.includes(value));
});
