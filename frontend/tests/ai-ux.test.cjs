const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const fixture = require('./result-fixture.cjs');
const { findingGuidance, semanticGuidance, needsVerification } = load('findingGuidance');
const { FindingRemediation } = load('FindingRemediation');
const render = props => renderToStaticMarkup(React.createElement(FindingRemediation, props));

test('strong secret guidance is actionable without claiming a live credential or proven attack', () => {
  const result = fixture(), finding = result.riskAssessment.codeFindings[0], vulnerability = result.vulnerabilities[0];
  const before = JSON.stringify(result);
  const html = render({ finding, vulnerability, snapshot: result.remediation });
  for (const text of ['실제로 유효한 값인지', '가능한 예시', '폐기·교체', '환경변수', '같은 프로젝트로 다시 검사', '템플릿 가이드']) assert.ok(html.includes(text), text);
  assert.equal(needsVerification(finding, vulnerability), false);
  assert.equal(JSON.stringify(result), before);
});

test('uncertain secret uses verification-first copy but never changes server priority', () => {
  const result = fixture(), finding = result.riskAssessment.codeFindings[0];
  for (const change of [{ confidence: 'LOW' }, { falsePositiveRisk: 'HIGH' }]) {
    const v = { ...result.vulnerabilities[0], ...change };
    assert.equal(needsVerification(finding, v), true);
    const html = render({ finding, vulnerability: v, snapshot: result.remediation });
    for (const text of ['실제 비밀번호나 API Key인지', '예제·테스트용', '문제가 확인되면', '처리 순서: 반드시 처리']) assert.ok(html.includes(text), text);
    assert.equal(finding.priority, 'BLOCKING');
  }
});

test('manual semantic instructions use owned test accounts, not technical authorization jargon', () => {
  const guide = semanticGuidance('IDOR');
  const text = JSON.stringify(guide);
  for (const word of ['Controller', 'Service', 'Authorization', 'Resource Owner']) assert.ok(!text.includes(word));
  for (const word of ['본인이 관리하는', 'A와 B', '거부되는지', '추가하세요']) assert.ok(text.includes(word));
  assert.ok(semanticGuidance('future-unknown-type').summary.includes('확정된 상태는 아닙니다'));
});

test('version uncertainty and lookup failure have different manual checks and never imply safe', () => {
  const base = { ...fixture().riskAssessment.reviewRequirements[0] };
  const version = findingGuidance({ ...base, reasonCode: 'UNRESOLVED_VERSION' });
  const lookup = findingGuidance({ ...base, reasonCode: 'INCOMPLETE_SCA' });
  const threat = findingGuidance({ ...base, reasonCode: 'INCOMPLETE_THREAT_INTELLIGENCE' });
  assert.ok(version.summary.includes('정확한 버전'));
  assert.ok(lookup.steps.some(s => s.includes('외부 조회 실패')));
  assert.ok(threat.steps.some(s => s.includes('악용 정보')));
  for (const guide of [version, lookup, threat]) assert.ok(guide.risk.includes('안전하다는 뜻이 아닙니다'));
});

test('generated, template, unavailable and missing snapshots retain honest provenance', () => {
  const result = fixture(), finding = result.riskAssessment.codeFindings[0];
  for (const [status, label] of [['GENERATED', 'AI 생성'], ['TEMPLATE', '템플릿 가이드'], ['FAILED', '생성 실패'], ['NOT_REQUESTED', '생성 대상 아님']]) {
    const snapshot = structuredClone(result.remediation);
    snapshot.findings[0].generationStatus = status;
    if (['FAILED', 'NOT_REQUESTED'].includes(status)) snapshot.findings[0].advice = null;
    const html = render({ finding, snapshot });
    assert.ok(html.includes(label));
    assert.equal(html.includes('코드에서 인증정보 제거'), !!snapshot.findings[0].advice);
  }
  assert.ok(render({ finding, snapshot: null }).includes('기본 안내'));
});

test('result navigation has no legacy AI generation handlers; compatibility APIs remain', () => {
  const app = fs.readFileSync(path.join(__dirname, '../src/App.tsx'), 'utf8')
    + fs.readFileSync(path.join(__dirname, '../src/components/ProjectReviewResult.tsx'), 'utf8');
  assert.doesNotMatch(app, /fetchAi(?:Review|ProjectSummary|Remediation|SecurityAudit|Priorities|Roadmap|ComparisonInsight)/);
  assert.doesNotMatch(app, /AiReviewSection|activeAiSubTab/);
  assert.ok(app.includes('window.confirm'));
  assert.ok(app.includes('downloadAiReviewReport'));
  const api = fs.readFileSync(path.join(__dirname, '../src/api/securityReviewApi.ts'), 'utf8');
  for (const name of ['fetchAiReview', 'fetchAiPriorities', 'downloadAiReviewReport']) assert.ok(api.includes(name));
});
