const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { ServerAnalysisSection } = require('./load-component.cjs')('ServerAnalysisSection');
const fixture = require('./server-analysis-fixture.cjs');
const render = snapshot => renderToStaticMarkup(React.createElement(ServerAnalysisSection, { snapshot }));
test('structural evidence shows source, propagation, file, uncertainty, and no automatic risk promotion', () => {
  const html = render(fixture());
  for (const phrase of ['functions/api/items.ts:3', 'functions/api/items.ts:6', '변수로 전달', '추가 확인 필요', '기존 점수·위험 판정·반드시 처리 건수에 합산하지 않습니다', '접근 권한 취약점으로 판단하지 않습니다']) assert.ok(html.includes(phrase), phrase);
});
test('old snapshots, failed analysis and no findings are not equated with safety', () => {
  assert.ok(render(null).includes('기록이 없습니다'));
  for (const status of ['PARTIAL', 'TIMEOUT', 'UNAVAILABLE', 'NOT_APPLICABLE', 'DISABLED']) {
    const html = render({ ...fixture(), status, findings: [] });
    assert.ok(html.includes('미검사·미지원 범위'));
    assert.ok(html.includes('전체 코드가 안전하다는 의미는 아닙니다'));
  }
});
test('API text is escaped and no source content or credential is reconstructed', () => {
  const data = fixture(); data.findings[0].message = '<script>synthetic</script>';
  const html = render(data);
  assert.ok(!html.includes('<script>')); assert.ok(html.includes('&lt;script&gt;'));
});
