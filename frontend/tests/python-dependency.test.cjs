const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const load = require('./load-component.cjs');
const { PythonDependencyDetails } = load('PythonDependencyDetails');
const { DependencyFindingCard } = load('DependencyFindingCard');
const { DependencySecuritySection } = load('DependencySecuritySection');
const { dependencyActionGroups } = load('DependencyContextDetails');
const fixture = require('./python-fixture.cjs');
const render = (component, props) => renderToStaticMarkup(React.createElement(component, props));
test('Python declarations expose actual constraint location without claiming installed runtime or source analysis', () => {
  const sca = fixture();
  const html = render(PythonDependencyDetails, { locations: sca.components });
  for (const text of ['requirements-dev.txt:3', 'constraints.txt:2', '파일명상 개발', '환경 조건은 평가하지', '실제 설치', '간접 의존성 전체']) assert.ok(html.includes(text), text);
  sca.components[0].python.versionOrigin = 'CONSTRAINT_PIN';
  sca.components[0].python.markerStatus = 'NONE';
  const groups = dependencyActionGroups(sca);
  assert.ok(JSON.stringify(groups).includes('constraints.txt'));
});
test('PyPI advisory preserves separate fix branches and escapes supplied text', () => {
  const sca = fixture(); sca.dependencyVulnerabilities[0].summary = '<script>synthetic</script>';
  const html = render(DependencyFindingCard, { dependency: sca.dependencyVulnerabilities[0], components: sca.components });
  for (const text of ['정적 선언에서 확인한', 'Python 서버 코드', 'OSV 버전 범위 근거', '2.1.1', '3.0.2', '호환성을 보장하지']) assert.ok(html.includes(text), text);
  assert.ok(html.includes('&lt;script&gt;')); assert.ok(!html.includes('<script>'));
});
test('Python failed lookup, range, and absent legacy context stay unknown', () => {
  for (const status of ['PARTIAL', 'UNAVAILABLE']) {
    const sca = fixture(); sca.status = status; sca.dependencyVulnerabilities = [];
    sca.warnings = ['OSV 조회 미완료'];
    sca.components[0].versionResolution = 'RANGE'; sca.components[0].version = '>=1.0';
    const html = render(DependencySecuritySection, { sca });
    assert.ok(html.includes('OSV 조회 미완료')); assert.ok(html.includes('Python'));
    assert.ok(!html.includes('알려진 취약점이 반환되지 않았습니다'));
  }
  assert.ok(render(PythonDependencyDetails, { locations: [] }).includes('추가 선언 근거가 없습니다'));
});
