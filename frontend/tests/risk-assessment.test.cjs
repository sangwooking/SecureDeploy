const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { RiskAssessmentSection, FindingPriority } = require('./load-component.cjs')('RiskAssessmentSection');
const { DependencySecuritySection } = require('./load-component.cjs')('DependencySecuritySection');
const render = assessment => renderToStaticMarkup(React.createElement(RiskAssessmentSection, { assessment }));
const counts = { BLOCKING: 0, SHOULD_FIX: 0, REVIEW_REQUIRED: 0, INFORMATIONAL: 0 };
function fixture(status = 'REVIEW_REQUIRED') {
  return {
    policyVersion: 'risk-v1', prioritizedDeploymentAssessment: status,
    assessmentReason: '자동 판단에 필요한 정보가 부족합니다.',
    prioritySummary: { ...counts, REVIEW_REQUIRED: 1 },
    prioritySummaryBySource: { CODE: counts, DEPENDENCY: counts, ANALYSIS: { ...counts, REVIEW_REQUIRED: 1 } },
    assessmentCoverage: { ruleEngine: 'COMPLETE', sca: 'FAILED', ai: 'NOT_INCLUDED', scopeNote: '테스트 분석 범위' },
    reviewRequirements: [{ findingId: 'coverage:sca', priority: 'REVIEW_REQUIRED', priorityReason: '조회 실패', sourceFiles: [] }],
  };
}
test('incomplete assessment is distinct from READY and retains its cause', () => {
  const html = render(fixture());
  for (const value of ['REVIEW_REQUIRED', 'FAILED', '조회 실패', 'risk-v1']) assert.ok(html.includes(value));
  assert.ok(!html.includes('assessment-ready'));
});
test('old reviews do not invent a priority or readiness assessment', () => {
  const html = render(null);
  assert.ok(html.includes('재분석이 필요합니다'));
  assert.ok(!html.includes('READY'));
  const priority = renderToStaticMarkup(React.createElement(FindingPriority));
  assert.ok(priority.includes('우선순위 평가 없음'));
  assert.ok(!priority.includes('INFORMATIONAL'));
});
test('each supported assessment preserves the server-provided status', () => {
  for (const status of ['BLOCKED', 'REVIEW_REQUIRED', 'READY_WITH_WARNINGS', 'READY']) {
    const html = render(fixture(status));
    assert.ok(html.includes('<strong>' + status + '</strong>'));
    assert.ok(html.includes('READY도 절대적 안전을 보장하지 않습니다'));
    assert.ok(html.includes('수정 완료 표시만으로 변경되지 않으며'));
  }
});
test('priority reasons are escaped and can differ from severity', () => {
  const html = renderToStaticMarkup(React.createElement(FindingPriority, { finding: {
    priority: 'SHOULD_FIX', priorityReason: '<script>fixture only</script>',
  } }));
  assert.ok(html.includes('SHOULD_FIX'));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!html.includes('<script>'));
});
test('dependency priority joins by package version and advisory, not sorted array index', () => {
  const finding = { ecosystem: 'NPM', packageName: 'fixture', installedVersion: '1.0.0', osvId: 'TEST-1',
    severity: 'HIGH', aliases: [], fixedVersions: [], cvssScore: null, sourceFiles: ['package.json'], referenceUrls: [] };
  const sca = { status: 'COMPLETE', summary: { dependenciesDiscovered: 1, dependenciesAnalyzed: 1, vulnerableDependencies: 1,
    dependencyVulnerabilities: 1, unresolvedDependencies: 0, severityCounts: { HIGH: 1 } }, warnings: [], components: [], dependencyVulnerabilities: [finding] };
  const riskAssessment = { dependencyFindings: [
    { ecosystem: 'NPM', packageName: 'fixture', version: '2.0.0', advisoryId: 'TEST-1', priority: 'BLOCKING', priorityReason: 'wrong version' },
    { ecosystem: 'NPM', packageName: 'fixture', version: '1.0.0', advisoryId: 'TEST-1', priority: 'SHOULD_FIX', priorityReason: 'correct match' },
  ] };
  const html = renderToStaticMarkup(React.createElement(DependencySecuritySection, { sca, riskAssessment }));
  assert.ok(html.includes('SHOULD_FIX'));
  assert.ok(html.includes('correct match'));
  assert.ok(!html.includes('wrong version'));
});

test('canonical dependency cards replace duplicate raw advisories and preserve candidate context', () => {
  const dependency = { ecosystem: 'NPM', packageName: 'fixture', installedVersion: '1.0.0', osvId: 'CVE-2099-0001',
    severity: 'HIGH', aliases: ['OSV-1','GHSA-test-1111-2222'], fixedVersions: [], cvssScore: null, sourceFiles: ['package.json'], referenceUrls: [] };
  const sca = { status: 'COMPLETE', summary: { dependenciesDiscovered: 1, dependenciesAnalyzed: 1, vulnerableDependencies: 1,
    dependencyVulnerabilities: 2, unresolvedDependencies: 0, severityCounts: { HIGH: 2 } }, warnings: [], components: [],
    dependencyVulnerabilities: [dependency, dependency] };
  const riskAssessment = { ...fixture('READY_WITH_WARNINGS'), schemaVersion: 2, dependencyFindings: [{
    dependency, ecosystem: 'NPM', packageName: 'fixture', version: '1.0.0', advisoryId: 'CVE-2099-0001',
    priority: 'SHOULD_FIX', priorityReason: 'canonical advisory',
  }], dependencyCorrelations: [{ vulnerabilityId: 123, ruleId: 'VULNERABLE_NPM_DEPENDENCY', filePath: 'package.json', line: 2,
    observation: { packageName: 'fixture', version: '1.0.0', advisoryId: null }, reason: '보조 근거로 연결했습니다.' }] };
  const html = renderToStaticMarkup(React.createElement(DependencySecuritySection, { sca, riskAssessment }));
  assert.equal((html.match(/<article /g) || []).length, 1);
  assert.ok(html.includes('OSV-1, GHSA-test-1111-2222'));
  const assessmentHtml = render(riskAssessment);
  assert.ok(assessmentHtml.includes('Priority 별도 합산 없음'));
  assert.ok(assessmentHtml.includes('개별 CVE 미지정 후보'));
  assert.ok(assessmentHtml.includes('배포 판단의 기준'));
});
