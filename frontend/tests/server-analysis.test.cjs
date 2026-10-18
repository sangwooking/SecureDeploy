const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { ServerAnalysisSection } = require('./load-component.cjs')('ServerAnalysisSection');
const fixture = require('./server-analysis-fixture.cjs');
const render = snapshot => renderToStaticMarkup(React.createElement(ServerAnalysisSection, { snapshot }));
test('Python evidence shares the UI but keeps scope, guidance and counts separate from TypeScript', () => {
  const root = fixture();
  const py = fixture(); py.analyzerVersion = 'py-django-v1'; py.parserVersion = 'CPython-3.14.5';
  py.validatedFindings[0].sourceType = 'PYTHON_DATA_FLOW';
  py.validatedFindings[0].ruleId = 'PY_SQL_INPUT_FLOW';
  py.validatedFindings[0].recommendedAction = 'execute(sql, params) 또는 Django ORM 값 매개변수';
  root.pythonAnalysis = py;
  const html = render(root);
  for (const phrase of ['Python 서버 코드 흐름 검사', 'Django/DRF', '전체 Python 코드', 'execute(sql, params)', 'PYTHON_DATA_FLOW', 'NOT_COMPARED']) assert.ok(html.includes(phrase), phrase);
  assert.equal((html.match(/<article /g)||[]).length, 2);
  assert.ok(!render(fixture()).includes('Python 서버 코드 흐름 검사'));
});
test('structural evidence shows source, propagation, file, uncertainty, and no automatic risk promotion', () => {
  const html = render(fixture());
  for (const phrase of ['functions/api/items.ts:3', 'functions/api/items.ts:6', '변수로 전달', '추가 확인 필요', '기존 점수·위험 판정·반드시 처리 건수에 합산하지 않습니다', '접근 권한 취약점으로 판단하지 않습니다']) assert.ok(html.includes(phrase), phrase);
});
test('Python parsing, entry discovery, traced files and resource limits remain distinct', () => {
  const root=fixture(), py=fixture(); root.pythonAnalysis=py;
  py.analyzerVersion='py-django-v2'; py.findings=[];py.validatedFindings=[];
  py.files=[
    {filePath:'route.py',parseStatus:'PARSED',flowStatus:'NOT_SUPPORTED',entrypoints:0,functionsAnalyzed:0,limitations:[],selectionReason:'DJANGO_ROUTING_HINT'},
    {filePath:'handler.py',parseStatus:'PARSED',flowStatus:'PARTIAL',entrypoints:2,functionsAnalyzed:1,limitations:['CALL_TARGET_UNRESOLVED']},
    {filePath:'data.py',parseStatus:'LIMIT_EXCEEDED',flowStatus:'NOT_RUN',entrypoints:0,functionsAnalyzed:0,limitations:['FILE_COUNT_LIMIT']},
  ];
  const html=render(root);
  for (const phrase of ['파일 기록 3개','구문 파싱 2개','요청 진입점 2개','값 전달을 추적한 파일 1개','자원 제한 1개',
    '보안 검사를 모두 마쳤다는 뜻이 아닙니다','Django 경로 설정 후보','파일 수 상한']) assert.ok(html.includes(phrase),phrase);
  py.limitations.push('OMITTED_FILE_DETAILS_TRUNCATED');
  assert.ok(render(root).includes('표시 파일 수는 전체 파일 수가 아님'));
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
test('SSRF shows human actions and incomplete destination coverage without certifying network safety', () => {
  const snapshot=fixture();
  snapshot.findings[0].ruleId='TS_SSRF_INPUT_FLOW';
  snapshot.validatedFindings[0].ruleId='TS_SSRF_INPUT_FLOW';
  snapshot.validatedFindings[0].title='사용자가 입력한 주소로 서버가 요청을 보낼 수 있습니다';
  snapshot.httpUses=[{kind:'INPUT_IN_DESTINATION',controlledPart:'HOST_OR_AUTHORITY',location:snapshot.findings[0].sink,
    trace:[],defenses:[],limitations:['REDIRECT_DNS_REACHABILITY_NOT_VERIFIED']}];
  const html=render(snapshot);
  for(const phrase of ['사용자가 입력한 주소','서버 HTTP 요청 목적지 (1)','호스트 또는 주소 권한부','리다이렉트·DNS 재해석','안전하다고 보증하지 않습니다','NOT_COMPARED']) assert.ok(html.includes(phrase),phrase);
  assert.equal((html.match(/<article /g)||[]).length,1);
  assert.ok(render(fixture()).includes('HTTP 목적지 추적 기록이 없습니다'));
});
