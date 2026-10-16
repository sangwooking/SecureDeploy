const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const fixture = require('./dependency-guidance-fixture.cjs');
const { IncompleteDependencyCard, SupplementalDependencyResult } = load('IncompleteDependencyCard');
const { FindingRemediation } = load('FindingRemediation');
const { ReviewResultWorkspace } = load('ReviewResultWorkspace');
const { dependencyGuidance } = load('dependencyGuidance');
const render = (Component, props) => renderToStaticMarkup(React.createElement(Component, props));
const noMarkers = html => assert.doesNotMatch(html.replace(/(?:value|id)="[^"]*"/g, ''), /unresolved-package|\bunknown\b|\bnull\b|N\/A|99\.99\.99|invented-package/);

test('known name requires exact version and only asks for the missing value', () => {
  const finding = fixture().riskAssessment.reviewRequirements[0];
  const html = render(IncompleteDependencyCard, { finding, reviewId: 101 });
  for (const word of ['정확한 버전', 'backend/pom.xml', 'org.example:library', '확인하지 못했습니다', '버전을 알고 있어요', 'readOnly', 'dependencyManagement']) assert.ok(html.includes(word), word);
  assert.ok(!html.includes('보안 문제가 보고되어'));
  noMarkers(html);
});

test('missing identity explains uncertainty, real location and ecosystem-specific instructions', () => {
  const finding = fixture().riskAssessment.reviewRequirements[1];
  const html = render(IncompleteDependencyCard, { finding, reviewId: 101 });
  for (const word of ['라이브러리 정보를 끝까지', 'flutter_app/android/app/build.gradle.kts', 'gradle/libs.versions.toml', '추가 정보로 확인하기', '취약한지 안전한지 판단할 수 없습니다']) assert.ok(html.includes(word));
  noMarkers(html);
  assert.ok(!html.includes('package-lock.json'));
  const missing = render(IncompleteDependencyCard, { finding: { ...finding, sourceFiles: [] } });
  assert.ok(missing.includes('저장된 파일 위치는 확인하지 못했습니다'));
});

test('legacy AI advice cannot invent a package, CVE or fixed version for unresolved findings', () => {
  const data = fixture();
  const html = render(FindingRemediation, { finding: data.riskAssessment.reviewRequirements[1], snapshot: data.remediation, expanded: true });
  noMarkers(html);
  assert.ok(html.includes('확정할 수 없습니다'));
  assert.ok(html.includes('어디서 어떤 값을 찾나요?'));
});

test('supplemental outcomes retain provenance, uncertainty and official risk boundary', () => {
  const data = fixture();
  const before = JSON.stringify(data);
  for (const status of ['COMPLETE', 'PARTIAL', 'UNAVAILABLE', 'DISABLED']) {
    for (const findings of [[], data.sca.dependencyVulnerabilities]) {
      const html = render(SupplementalDependencyResult, { result: { provenance: 'USER_PROVIDED', status,
        packageName: 'fixture-library', version: '1.0.0', findings } });
      assert.ok(html.includes('사용자가 직접 입력한 정보로 확인한 결과입니다'));
      assert.ok(html.includes('배포 판단은 변경되지 않습니다'));
      if (status !== 'COMPLETE') {
        assert.ok(html.includes('확인하지 못했습니다'));
        assert.ok(!html.includes('보안 문제가 반환되지 않았습니다'));
      }
    }
  }
  const unsafeText = render(SupplementalDependencyResult, { result: { status: 'COMPLETE', packageName: '<script>alert(1)</script>', version: '1.0.0', findings: [] } });
  assert.ok(!unsafeText.includes('<script>'));
  assert.equal(JSON.stringify(data), before);
});

test('ZIP and GitHub use identical guidance; every result view hides internal markers', () => {
  const zip = fixture('ZIP'), github = fixture('GITHUB');
  assert.deepEqual(dependencyGuidance(zip.riskAssessment.reviewRequirements[1]), dependencyGuidance(github.riskAssessment.reviewRequirements[1]));
  for (const result of [zip, github]) for (const view of ['SUMMARY', 'REVIEW_REQUIRED', 'GUIDANCE', 'TECHNICAL']) {
    const before = JSON.stringify(result);
    const html = render(ReviewResultWorkspace, { result, view, onViewChange() {}, statusActions: { comments: {}, updatingId: null, onComment() {}, onStatus() {} } });
    noMarkers(html);
    assert.equal(JSON.stringify(result), before);
  }
});
