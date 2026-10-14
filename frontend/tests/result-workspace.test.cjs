const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const { ReviewResultWorkspace } = load('ReviewResultWorkspace');
const { reviewCounts, vulnerabilityForFinding, semanticStatusText, deploymentLabels } = load('reviewPresentation');
const { CodeFindingCard } = load('CodeFindingCard');
const { DependencyFindingCard } = load('DependencyFindingCard');
const fixture = require('./result-fixture.cjs');
const actions = { updatingId: null, comments: {}, onComment() {}, onStatus() {} };
const render = (result, view = 'SUMMARY') => renderToStaticMarkup(React.createElement(ReviewResultWorkspace, {
  result, view, onViewChange() {}, statusActions: actions, reportActions: null, progress: null, aiPanel: null,
}));

test('summary prioritizes deployment assessment over a perfect legacy score, hides technical details', () => {
  const result = fixture(), before = JSON.stringify(result);
  const html = render(result);
  for (const text of ['배포 전 수정 필요', '반드시 처리', '분석 확인 1 + AI 추가 후보 1', '가장 먼저 해야 할 일']) assert.ok(html.includes(text), text);
  for (const text of ['CVE-2099', 'HARDCODED_SECRET', 'fixture-model', 'Confidence', '100 / 100', 'AI_SECURITY_CANDIDATE']) assert.ok(!html.includes(text), text);
  assert.deepEqual(reviewCounts(result), { blocking: 1, review: 1, recommended: 1, candidates: 1 });
  assert.equal(JSON.stringify(result), before);
});

test('server priorities, not severity or AI confidence, determine the displayed groups', () => {
  const result = fixture();
  const mandatory = render(result, 'BLOCKING');
  assert.ok(mandatory.includes('API Key가 코드에 포함'));
  assert.ok(!mandatory.includes('AI_SECURITY_CANDIDATE'));
  assert.ok(!mandatory.includes('fixture-library'));
  const check = render(result, 'REVIEW_REQUIRED');
  assert.ok(check.includes('반드시 취약점이라는 뜻은 아닙니다'));
  assert.ok(check.includes('확정 취약점이 아닙니다'));
  assert.ok(check.includes('설치 버전을 확인하지 못했습니다'));
  const recommended = render(result, 'SHOULD_FIX');
  assert.ok(recommended.includes('fixture-library'));
  assert.ok(recommended.includes('참고 사항 (1건)'));
  assert.equal(result.riskAssessment.prioritizedDeploymentAssessment, 'BLOCKED');
});

test('each deployment verdict uses an explicit, qualified label without changing the enum', () => {
  for (const [status, label] of Object.entries(deploymentLabels)) {
    const result = fixture();
    result.riskAssessment.prioritizedDeploymentAssessment = status;
    const html = render(result);
    assert.ok(html.includes(label));
    assert.ok(html.includes('미발견이 완전한 안전을 뜻하지 않으며'));
    assert.equal(result.riskAssessment.prioritizedDeploymentAssessment, status);
  }
});

test('legacy results do not invent a readiness, priority, metadata, or zero count', () => {
  const result = { ...fixture(), riskAssessment: null, semanticReview: null, sca: null, remediation: null, scanMode: null };
  const html = render(result);
  assert.ok(html.includes('미평가'));
  assert.ok(html.includes('재분석 후 배포 여부'));
  assert.ok(!html.includes('현재 분석 범위에서는 배포 가능'));
  assert.ok(render(result, 'REVIEW_REQUIRED').includes('우선순위가 저장되지 않은 코드 문제'));
  const v = { ...result.vulnerabilities[0], confidence: undefined, falsePositiveRisk: undefined, analysisNote: null };
  const card = renderToStaticMarkup(React.createElement(CodeFindingCard, { vulnerability: v, statusActions: actions }));
  assert.ok(card.includes('정보 없음'));
  assert.ok(!card.includes('판단 근거'));
});

test('code evidence stays masked and escaped inside closed technical details', () => {
  const result = fixture();
  const html = render(result, 'BLOCKING');
  assert.match(html, /<details class="technical-details"><summary>기술 정보 보기/);
  assert.ok(html.includes('secret = &lt;redacted&gt;'));
  assert.ok(html.includes('Confidence'));
  assert.ok(html.includes('False Positive Risk'));
  assert.ok(html.includes('테스트 응답의 판단 근거'));
  assert.ok(!html.includes('<redacted>'));
});

test('dependency guidance uses reported fixes without promising compatible or universally safe versions', () => {
  const result = fixture();
  const dep = result.sca.dependencyVulnerabilities[0];
  const html = renderToStaticMarkup(React.createElement(DependencyFindingCard, { dependency: dep }));
  for (const text of ['알려진 수정 버전', '1.0.1, 2.0.0', '빌드와 관련 기능 테스트', '호환성을 보장하지 않습니다', '업데이트 방법 보기']) assert.ok(html.includes(text));
  assert.ok(!html.includes('javascript:'));
  assert.match(html, /<details class="technical-details"><summary>기술 정보 보기/);
  const unknown = renderToStaticMarkup(React.createElement(DependencyFindingCard, { dependency: { ...dep, fixedVersions: [] } }));
  assert.ok(unknown.includes('수정 버전을 확인하지 못했습니다'));
});

test('enhanced but disabled, unavailable, failed, and zero candidate states remain distinct from safe', () => {
  const snapshot = fixture().semanticReview;
  assert.ok(semanticStatusText({ ...snapshot, semanticReviewStatus: 'NOT_REQUESTED', requestCount: 0 }).includes('비활성화'));
  assert.ok(semanticStatusText({ ...snapshot, semanticReviewStatus: 'UNAVAILABLE', requestCount: 0 }).includes('실행할 수 없었습니다'));
  assert.ok(semanticStatusText({ ...snapshot, semanticReviewStatus: 'FAILED' }).includes('완료한 상태가 아닙니다'));
  const result = fixture();
  result.semanticReview = { ...snapshot, candidates: [] };
  const html = render(result, 'REVIEW_REQUIRED');
  assert.ok(html.includes('후보 0건은 안전을 의미하지 않습니다'));
  assert.equal(reviewCounts(result).blocking, 1);
});

test('ambiguous legacy joins do not attach another finding remediation to a location', () => {
  const result = fixture(), finding = { ...result.riskAssessment.codeFindings[0], vulnerabilityId: null };
  assert.equal(vulnerabilityForFinding(result, finding)?.vulnerabilityId, 51);
  result.vulnerabilities.push({ ...result.vulnerabilities[0], vulnerabilityId: 99, line: 60 });
  assert.equal(vulnerabilityForFinding(result, finding), undefined);
});

test('technical screen retains reference score and original snapshots without changing assessment', () => {
  const result = fixture();
  const html = render(result, 'TECHNICAL');
  for (const text of ['100 / 100', '참고 점수는 배포 허가가 아닙니다', 'BLOCKED', 'HARDCODED_SECRET', 'CVE-2099-0001']) assert.ok(html.includes(text));
});

test('guidance resolves advice by finding identity and keeps additional AI tools available', () => {
  const html = render(fixture(), 'GUIDANCE');
  for (const text of ['해결할 문제 선택', '코드에서 인증정보 제거', '수정 후 무엇을 확인하나요?', 'AI와 더 자세히 검토하기']) assert.ok(html.includes(text));
});
