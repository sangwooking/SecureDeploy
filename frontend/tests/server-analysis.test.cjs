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
    const html = render({ ...fixture(), status, findings: [], validatedFindings: [] });
    assert.ok(html.includes('미검사·미지원 범위'));
    assert.ok(html.includes('전체 코드가 안전하다는 의미는 아닙니다'));
  }
});
test('API text is escaped and no source content or credential is reconstructed', () => {
  const data = fixture(); data.validatedFindings[0].riskExplanation = '<script>synthetic</script>';
  const html = render(data);
  assert.ok(!html.includes('<script>')); assert.ok(html.includes('&lt;script&gt;'));
});
test('validated finding has actions and stable identity without duplicate candidate or invented certainty', () => {
  const html = render(fixture());
  for (const phrase of ['ts-flow:synthetic-only','어떤 입력인가요?','왜 확인해야 하나요?','어떻게 수정하나요?','수정 후 확인','NOT_COMPARED','functions/api/items.ts:7']) assert.ok(html.includes(phrase), phrase);
  assert.equal((html.match(/<article /g) || []).length, 1);
  assert.ok(!html.includes('추가 문맥이 필요한 후보'));
});
test('legacy and unresolved candidates are preserved without being promoted', () => {
  const legacy = fixture(); delete legacy.validatedFindings; legacy.analyzerVersion = 'ts-server-v1';
  assert.ok(render(legacy).includes('새 기준으로 추측하여 승격하지 않습니다'));
  const uncertain = fixture(); uncertain.validatedFindings = []; uncertain.findings[0].confidence = 'MEDIUM';
  assert.ok(render(uncertain).includes('중간 처리 또는 실행 호출을 충분히 확인하지 못해'));
});
