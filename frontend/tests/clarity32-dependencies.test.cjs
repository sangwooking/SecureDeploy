const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const progressFixture = require('./progress-fixture.cjs');
const { DependencySecuritySection } = load('DependencySecuritySection');
const { DependencyContextDetails } = load('DependencyContextDetails');
const { ReviewProgressPanel } = load('ReviewProgressPanel');
const render = (Component, props) => renderToStaticMarkup(React.createElement(Component, props));

function dependency() {
  return { ecosystem: 'NPM', packageName: 'fixture-library', installedVersion: '1.0.0',
    osvId: 'GHSA-fixture-one', aliases: [], summary: 'Synthetic advisory', severity: null,
    cvssScore: null, fixedVersions: [], referenceUrls: [], sourceFiles: ['package-lock.json'] };
}
function sca() {
  const dep = dependency();
  return { schemaVersion: 2, status: 'COMPLETE', analyzedAt: '2026-10-28T00:00:00Z',
    summary: { dependenciesDiscovered: 3, dependenciesAnalyzed: 3, unresolvedDependencies: 0,
      vulnerableDependencies: 1, dependencyVulnerabilities: 2, severityCounts: { UNKNOWN: 2 } },
    components: [], dependencyVulnerabilities: [dep, { ...dep, osvId: 'GHSA-fixture-two' }], warnings: [] };
}

test('SCA separates package-version impact, raw advisory items and canonical displayed items', () => {
  const data = sca();
  const props = { sca: data, riskAssessment: { schemaVersion: 2,
    dependencyFindings: [{ dependency: data.dependencyVulnerabilities[0] }], reviewRequirements: [] } };
  const before = JSON.stringify(props);
  const html = render(DependencySecuritySection, props);
  assert.match(html, /발견한 패키지·버전 조합<\/dt><dd>3<\/dd>/);
  assert.match(html, /조회 완료 패키지·버전 조합<\/dt><dd>3<\/dd>/);
  assert.match(html, /보안 공지가 있는 패키지·버전 조합<\/dt><dd>1<\/dd>/);
  assert.match(html, /표시된 보안 공지·패키지·버전 항목<\/dt><dd>1<\/dd>/);
  assert.ok(html.includes('원본 조회의 공지 항목은 2개'));
  assert.ok(html.includes('수정 작업 수와 다릅니다'));
  assert.equal((html.match(/<article /g) || []).length, 1);
  assert.equal(JSON.stringify(props), before);
  const legacy = render(DependencySecuritySection, { sca: data });
  assert.match(legacy, /표시된 보안 공지·패키지·버전 항목<\/dt><dd>2<\/dd>/);
});

test('zero advisories do not erase incomplete, disabled, absent or legacy SCA states', () => {
  for (const status of ['PARTIAL', 'UNAVAILABLE', 'DISABLED', 'NO_MANIFEST']) {
    const data = sca(); data.status = status; data.dependencyVulnerabilities = [];
    data.summary = { ...data.summary, vulnerableDependencies: 0, dependencyVulnerabilities: 0 };
    const html = render(DependencySecuritySection, { sca: data });
    assert.ok(html.includes('안전 여부는 확인되지 않았습니다'));
    assert.ok(!html.includes('알려진 취약점이 반환되지 않았습니다'));
  }
  assert.ok(render(DependencySecuritySection, { sca: null }).includes('검사 결과가 없습니다'));
  const data = sca(); data.dependencyVulnerabilities = [];
  const html = render(DependencySecuritySection, { sca: data });
  assert.ok(html.includes('프로젝트 전체의 안전을 보장하지 않습니다'));
});

test('mixed dependency context preserves missing paths, UNKNOWN environment and nullable directness', () => {
  const location = { ecosystem: 'NPM', packageName: 'fixture-library', version: '1.0.0',
    direct: null, sourceFile: 'package-lock.json', line: 0, versionResolution: 'EXACT',
    context: { environment: 'UNKNOWN', installedPath: null, lockLine: 0,
      paths: [], pathsComplete: false, limitations: ['<script>synthetic</script>'] } };
  const props = { locations: [location, { ...location, sourceFile: 'nested/package-lock.json', context: null }] };
  const before = JSON.stringify(props);
  const html = render(DependencyContextDetails, props);
  for (const text of ['일부 버전 확인 위치에는 상위 의존성 경로 기록이 없습니다', '사용 환경 확인 불가',
    '직접/간접 미확인', '모든 경로를 확인하지 못했습니다', '&lt;script&gt;synthetic']) assert.ok(html.includes(text), text);
  assert.ok(!html.includes('운영 의존성 선언 경로'));
  assert.ok(!html.includes('<script>'));
  assert.equal(JSON.stringify(props), before);
  assert.ok(render(DependencyContextDetails, { locations: [] }).includes('상위 의존성 경로가 없습니다'));
});

test('all comparison statuses expose saved scope and keep unknown and NOT_COMPARED distinct from resolution', () => {
  for (const status of ['COMPLETE', 'PARTIAL', 'UNAVAILABLE', 'NO_BASELINE']) {
    const result = progressFixture(); result.comparison.status = status;
    result.comparison.notices = ['서버 흐름 Finding은 해결 건수에 미포함', '<script>scope</script>'];
    if (status === 'NO_BASELINE') result.comparison.assessmentBefore = null;
    const before = JSON.stringify(result);
    const html = render(ReviewProgressPanel, { result });
    const context = html.indexOf('<details class="comparison-context"');
    assert.ok(html.slice(0, context).includes(require('./load-component.cjs')('uiLanguage').inspectionLabel(status)));
    assert.ok(html.slice(0, context).includes(`<p>${status} ·`));
    assert.ok(html.slice(0, context).includes('서버 흐름 Finding은 해결 건수에 미포함'));
    assert.ok(html.includes('NOT_COMPARED'));
    assert.match(html, /비교 확인 불가 <strong>1<\/strong>/);
    assert.ok(html.includes('실제 취약점 해결이나 전체 안전성의 증명이 아닙니다'));
    assert.ok(html.includes('코드 변경으로 새로 생겼다는 뜻은 아닙니다'));
    assert.ok(html.includes('&lt;script&gt;scope'));
    assert.ok(!html.includes('<script>'));
    if (status === 'NO_BASELINE') assert.ok(html.includes('평가 정보 없음'));
    assert.equal(JSON.stringify(result), before);
  }
});

test('resolved dependency keeps absent current Finding separate from observed declaration versions', () => {
  for (const versions of [[], ['^2.0.0', '미확정', '<img src=x>']]) {
    const result = progressFixture();
    const entry = result.comparison.findings.find(e => e.status === 'RESOLVED');
    entry.before = { code: null, risk: { source: 'DEPENDENCY', packageName: 'fixture-library',
      version: '1.0.0', priority: 'SHOULD_FIX', sourceFiles: ['package-lock.json'] } };
    entry.currentVersions = versions;
    const before = JSON.stringify(result);
    const html = render(ReviewProgressPanel, { result });
    assert.ok(html.includes('우선순위: 수정 권장 → 현재 Finding 없음'));
    assert.ok(html.includes('이전 Finding 버전: 1.0.0 / 현재 Finding 버전: 정보 없음'));
    assert.ok(html.includes('실제 설치 버전이나 안전한 버전이라는 뜻은 아닙니다'));
    assert.ok(html.includes('현재 의존성 선언에서 관찰한 버전: ' + (versions.length ? '^2.0.0, 미확정, &lt;img src=x&gt;' : '확인 불가')));
    assert.ok(!html.includes('<img'));
    assert.ok(html.includes('이전 기술 정보 보기'));
    assert.equal(JSON.stringify(result), before);
  }
});
