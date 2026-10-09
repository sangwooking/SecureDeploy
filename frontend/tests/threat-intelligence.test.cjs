const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { ThreatIntelligenceDetails } = require('./load-component.cjs')('ThreatIntelligenceDetails');
const finding = { osvId: 'GHSA-fixture', aliases: ['CVE-2099-0001'] };
const data = { cve: 'CVE-2099-0001',
  epss: { score: .82, percentile: .98, status: 'AVAILABLE', date: '2026-10-07', fetchedAt: '2026-10-07T12:00:00Z' },
  kev: { knownExploited: true, status: 'AVAILABLE', requiredAction: '<script>fixture</script>' } };
function render(snapshot, dep = finding) {
  return renderToStaticMarkup(React.createElement(ThreatIntelligenceDetails, { finding: dep, snapshot }));
}
function snapshot(value = data) { return { observedAt: '2026-10-07T12:00:00Z', cves: { 'CVE-2099-0001': value } }; }
test('EPSS probability and percentile are distinct and KEV reports known exploitation', () => {
  const html = render(snapshot());
  for (const text of ['0.82000', '98.00 백분위', 'YES', '향후 30일', '해킹 확률이 아닙니다', 'FIRST EPSS', 'CISA KEV']) assert.ok(html.includes(text));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!html.includes('<script>'));
});
test('missing or stale negative KEV is unknown and EPSS missing is not zero', () => {
  for (const status of ['UNAVAILABLE', 'STALE', 'NOT_REQUESTED']) {
    const html = render(snapshot({ epss: { score: null, percentile: null, status }, kev: { knownExploited: false, status } }));
    assert.ok(html.includes('미확인'));
    assert.ok(!html.includes('NO ·'));
    assert.ok(!html.includes('0.00000'));
  }
});
test('fresh KEV negative and old confirmed exploitation stay distinguishable', () => {
  assert.ok(render(snapshot({ ...data, kev: { status: 'AVAILABLE', knownExploited: false } })).includes('NO · 조회한 catalog에 미수록'));
  const stale = render(snapshot({ ...data, kev: { status: 'STALE', knownExploited: true } }));
  assert.ok(stale.includes('YES'));
  assert.ok(stale.includes('최신 확인 필요'));
});
test('legacy absent snapshot and advisory without CVE do not invent intelligence', () => {
  assert.ok(render(null).includes('재분석이 필요합니다'));
  assert.ok(render(snapshot(), { osvId: 'OSV-no-cve', aliases: [] }).includes('CVE 연결 없음'));
  assert.ok(!render(snapshot(), { osvId: 'OSV-no-cve', aliases: [] }).includes('YES'));
});
