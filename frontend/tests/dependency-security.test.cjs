const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');

const componentExports = require('./load-component.cjs')('DependencySecuritySection');
const render = (sca) => renderToStaticMarkup(React.createElement(componentExports.DependencySecuritySection, { sca }));
const renderNotice = (sca) => renderToStaticMarkup(React.createElement(componentExports.ScaAssessmentNotice, { sca }));

function fixture(overrides = {}) {
  return {
    status: 'COMPLETE', analyzedAt: '2026-01-01T00:00:00Z',
    summary: { dependenciesDiscovered: 2, dependenciesAnalyzed: 2, unresolvedDependencies: 0,
      vulnerableDependencies: 1, dependencyVulnerabilities: 1, severityCounts: { HIGH: 1, UNKNOWN: 0 } },
    components: [],
    dependencyVulnerabilities: [{
      ecosystem: 'MAVEN', packageName: 'org.example:fixture', installedVersion: '1.0.0',
      osvId: 'GHSA-fixture-1', aliases: ['CVE-2099-0001'], summary: '<script>fake payload</script>',
      severity: 'HIGH', cvssScore: null, cvssVectors: [], fixedVersions: ['2.0.0'],
      published: null, modified: null, referenceUrls: ['javascript:alert(1)', 'https://example.invalid/advisory'],
      sourceFiles: ['pom.xml'],
    }], warnings: [], ...overrides,
  };
}
test('renders package identity, severity and fixes while escaping advisory text', () => {
  const html = render(fixture());
  for (const text of ['org.example:fixture', '1.0.0', '2.0.0', 'GHSA-fixture-1', 'CVE-2099-0001', 'HIGH']) assert.ok(html.includes(text));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!html.includes('javascript:'));
  assert.ok(html.includes('기존 규칙 기반 점수에는 미반영'));
});
test('partial and unavailable results never show a clean bill of health', () => {
  for (const status of ['PARTIAL', 'UNAVAILABLE']) {
    const html = render(fixture({ status, dependencyVulnerabilities: [], warnings: ['OSV 조회 미완료'] }));
    assert.ok(html.includes('OSV 조회 미완료'));
    assert.ok(html.includes('미조회 항목'));
    assert.ok(!html.includes('알려진 취약점이 반환되지 않았습니다'));
  }
});
test('old reviews and unknown severity have explicit unavailable states', () => {
  assert.ok(render(null).includes('SCA 결과가 없습니다'));
  const data = fixture();
  data.dependencyVulnerabilities[0].severity = null;
  data.dependencyVulnerabilities[0].fixedVersions = [];
  const html = render(data);
  assert.ok(html.includes('미확인'));
  assert.ok(html.includes('확인되지 않음'));
  assert.ok(!html.includes('severity-low'));
});
test('unresolved declarations remain visible', () => {
  const html = render(fixture({ status: 'PARTIAL', components: [{
    ecosystem: 'NPM', packageName: 'fixture', version: '^1.0.0', scope: 'dependencies',
    direct: true, sourceFile: 'package.json', line: 0, versionResolution: 'RANGE',
  }] }));
  assert.ok(html.includes('버전 확인이 필요한 의존성'));
  assert.ok(html.includes('^1.0.0'));
});

test('deployment summary distinguishes incomplete SCA from the legacy rule score', () => {
  for (const status of ['PARTIAL', 'UNAVAILABLE', 'DISABLED', 'NO_MANIFEST']) {
    const html = renderNotice(fixture({ status, dependencyVulnerabilities: [] }));
    assert.ok(html.includes('의존성 보안 확인 미완료'));
    assert.ok(html.includes('안전 여부는 확인되지 않았습니다'));
    assert.ok(html.includes('규칙 기반 결과'));
  }
  assert.ok(renderNotice(fixture()).includes('의존성 취약점 1건 확인'));
  assert.ok(renderNotice(null).includes('의존성 보안 확인 미완료'));
});
