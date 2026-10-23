const { test } = require('node:test');
const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { ServerAnalysisSection } = require('./load-component.cjs')('ServerAnalysisSection');
const fixture = require('./server-analysis-fixture.cjs');
const render = snapshot => renderToStaticMarkup(React.createElement(ServerAnalysisSection, { snapshot }));
test('structural finding file navigation is opt-in and absent for read-only results',()=>{
  assert.ok(!render(fixture()).includes('이 파일 수정하기'));
  const html=renderToStaticMarkup(React.createElement(ServerAnalysisSection,{snapshot:fixture(),onEditFile:()=>{}}));
  assert.ok(html.includes('이 파일 수정하기'));assert.ok(html.includes('NOT_COMPARED'));
});
test('combined code and SQL selection is not confused with parsing or verified flows',()=>{
  const data=fixture();data.analyzerVersion='ts-server-v16';data.nodeUses=[];
  data.selectionCoverage={discoveredFiles:249,submittedFiles:100,omittedFiles:149,omittedDetails:49,submittedCharacters:450000,omissionReasons:{SOURCE_FILE_COUNT_LIMIT:149}};
  data.files[0].selectionReason='TS_RELATED_IMPORT_HINT';
  const html=render(data);
  for(const phrase of ['JS/TS·정책 SQL 후보 249개','분석 입력 선택 100개','미선택 149개','미선택 파일은 안전으로 처리하지 않습니다',
    '서버 후보의 제한된 상대 import 관계','구문 파싱이나 보안 흐름 검증 완료가 아닙니다'])assert.ok(html.includes(phrase),phrase);
});
test('Next declarations, invocation uncertainty and client bundle scope are separated',()=>{
  const data=fixture();data.analyzerVersion='ts-server-v13';data.nodeUses=[];
  data.files[0].limitations.push('NEXT_SERVER_FUNCTION_INVOCATION_NOT_VERIFIED','NEXT_PAGES_API_NOT_SUPPORTED');
  data.authorizationContexts[0].entry.kind='NEXT_SERVER_FUNCTION';
  const html=render(data);
  for(const phrase of ['Next.js 요청 함수 0곳','서버 함수 선언 1곳','실제 호출·인증·데이터 접근권한의 증명이 아닙니다',
    '실제 클라이언트 번들은 검사하지 않았습니다','Pages Router API 요청 흐름은 이번 분석 범위 밖'])assert.ok(html.includes(phrase),phrase);
});
test('entry stages distinguish static registration and declared Passport callbacks from security proof',()=>{
  const snapshot=fixture();snapshot.analyzerVersion='ts-server-v11';snapshot.nodeUses=[];
  for(const kind of ['ENTRY_REGISTERED','CALL_LINKED','CALLBACK_BOUND','AUTHENTICATOR_REFERENCED'])snapshot.nodeUses.push({
    ruleId:'JS_SERVER_ENTRY_CONTEXT',kind,operation:'STATIC_ONLY',location:{filePath:'server.cjs',line:1},trace:[],
    limitations:['INITIALIZATION_AND_REQUEST_DISPATCH_NOT_VERIFIED']});
  const html=render(snapshot);
  for(const phrase of ['요청 등록 1곳','Router 반환 연결 1곳','전체 보안 흐름 검증이나 안전 판정이 아닙니다',
    'Passport 콜백 등록 선언 확인','초기화 실행과 실제 요청 전달은 미확인'])assert.ok(html.includes(phrase),phrase);
  snapshot.analyzerVersion='ts-server-v10';assert.ok(!render(snapshot).includes('소스 기록'));
});
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
  for (const phrase of ['ts-flow:synthetic-only','어떤 입력인가요?','입력 경로와 수정 방법','어떻게 수정하나요?','수정 후 확인','NOT_COMPARED','functions/api/items.ts:7']) assert.ok(html.includes(phrase), phrase);
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
test('Express evidence keeps unknown database receivers and resource authorization separate',()=>{
  const data=fixture();data.validatedFindings=[];data.findings[0].ruleId='JS_EVAL_INPUT_FLOW';
  data.findings[0].source.kind='EXPRESS_BODY';data.findings[0].message='코드 실행 검토';
  data.nodeUses=[{ruleId:'JS_MONGO_WHERE_INPUT_FLOW',kind:'RECEIVER_NOT_VERIFIED',operation:'find',location:data.findings[0].sink,trace:[],limitations:['MONGODB_RECEIVER_OR_OBJECT_FLOW_UNRESOLVED']}];
  const html=render(data);
  for(const text of ['입력값을 코드로 실행하는지','요청 본문','Express 코드 실행·데이터 접근 근거 (1)','객체 출처 또는 값 전달을 확인하지 못함','소유권 검증의 증명이 아니며'])assert.ok(html.includes(text),text);
  assert.ok(!html.includes('요청 값이 데이터베이스 쿼리에 들어갑니다'));
});
test('constructor effect proof and cursor creation are not execution or whole-function safety',()=>{
  const data=fixture();data.validatedFindings=[];
  data.nodeUses=['CONSTRUCTOR_SUMMARY_MUST','CONSTRUCTOR_SUMMARY_UNKNOWN','CURSOR_CREATED_EXECUTION_NOT_OBSERVED'].map(kind=>({ruleId:'JS_CONSTRUCTOR_EFFECT',kind,operation:'STATIC_ONLY',location:data.findings[0].sink,trace:[],limitations:[]}));
  const html=render(data);
  for(const phrase of ['제한된 생성자의 필드 전달·읽기 효과 확인','생성자 효과를 확인하지 못함','커서 구성 단계 · 이 근거만으로 실행은 미확인'])assert.ok(html.includes(phrase),phrase);
});
