const {test}=require('node:test');
const assert=require('node:assert/strict');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {ReviewSummaryPanel,summaryStateLabel}=require('./load-component.cjs')('ReviewSummaryPanel');
const fixture=()=>require('./summary-fixture.cjs')()[0].result;
const render=result=>renderToStaticMarkup(React.createElement(ReviewSummaryPanel,{result,
  actions:React.createElement('button',null,'report-action')}));
const visible=html=>html.split('<details')[0];

test('four independent facts retain raw states; perfect score is not an overall safe verdict',()=>{
  const html=render(fixture()),top=visible(html);
  for(const label of ['저장된 위험 정책 판단','기존 규칙 기반 참고 점수','전체 검사 범위 기록','라이브러리 외부 조회'])assert.ok(top.includes(label),label);
  for(const state of ['READY','PARTIAL','DISABLED'])assert.ok(top.includes(`<code>${state}</code>`),state);
  for(const text of ['100 / 100','100점도 전체 안전을 뜻하지 않습니다','배포 승인·전체 안전 판정이 아닙니다',
    '일부만 확인했으며 미검사 범위가 남아 있습니다','실제 공격·배포 상태·사용자 권한은 미확인','report-action'])assert.ok(top.includes(text),text);
  assert.equal((top.match(/<dt>/g)||[]).length,7);
  assert.ok(!/class="[^"]*(?:success|safe|green)/i.test(html));
});

test('saved policy and score are not replaced by a conflicting summary snapshot',()=>{
  const r=fixture();r.securityScore=37;r.resultSummary.referenceScore=100;
  r.riskAssessment.prioritizedDeploymentAssessment='BLOCKED';r.resultSummary.policyAssessment='READY';
  const html=render(r),top=visible(html);
  assert.ok(top.includes('반드시 처리할 문제부터 확인하세요'));
  assert.ok(top.includes('<code>BLOCKED</code>'));assert.ok(top.includes('37 / 100'));
  assert.ok(!top.includes('100 / 100'));
  assert.ok(html.includes('<code>READY</code>'));assert.ok(html.includes('100 · <code>RULE_ENGINE_REFERENCE_ONLY</code>'));
});

test('critical unknowns stay visible while reason and technical evidence are collapsed',()=>{
  const r=fixture();Object.assign(r.resultSummary,{reason:'long-evidence-reason',authContextObserved:true,
    rlsDeclarationsObserved:true,unresolvedDependencies:3,importantRuleSignals:2});
  const html=render(r),top=visible(html);
  for(const text of ['로그인 성공이나 리소스 소유권 검증을 뜻하지 않습니다','운영 DB 적용과 실제 역할은 미확인',
    '버전 미확정 3건','HIGH/CRITICAL 규칙 경고 2건','정책 SQL 분석 미실행 2개','NOT_REQUESTED'])assert.ok(top.includes(text),text);
  assert.ok(!top.includes('long-evidence-reason'));assert.ok(html.includes('long-evidence-reason'));
  assert.ok(html.includes('<details class="summary-detail"><summary>'));
  assert.ok(!html.includes('<details class="summary-detail" open'));
});

test('all analyzer records, unknown states, zero counts and limitations survive escaped',()=>{
  const r=fixture();Object.assign(r.resultSummary,{coverageStatus:'FUTURE_COVERAGE',scaStatus:'FUTURE_SCA',
    riskCalculationStatus:'FUTURE_RISK',semanticStatus:'FUTURE_AI',limitations:['evidence <img src=x>'],
    analyzers:[{analyzer:'CUSTOM_ENGINE',status:'FUTURE_ANALYZER',observations:{AST_PARSE_FAILED:4,CUSTOM_OBSERVATION:9,ZERO:0}}]});
  const html=render(r);
  for(const text of ['FUTURE_COVERAGE','FUTURE_SCA','FUTURE_RISK','FUTURE_AI','FUTURE_ANALYZER',
    'CUSTOM_ENGINE','CUSTOM_OBSERVATION</code>: 9','ZERO</code>: 0','AST_PARSE_FAILED</code>: 4',
    'evidence &lt;img src=x&gt;','NOT_COMPARED','NOT_PERFORMED','review-summary-v1','REVIEW_NEEDED'])assert.ok(html.includes(text),text);
  assert.ok(visible(html).includes('구문 파싱 실패 4개'));assert.ok(!html.includes('<img'));
  assert.equal(summaryStateLabel('FUTURE'),'확인 상태의 기술 정보 검토 필요');
});

for(const state of ['PARTIAL','FAILED','UNKNOWN','NOT_RECORDED','UNAVAILABLE','DISABLED','NO_MANIFEST','COMPLETE']){
  test(`coverage and SCA preserve exact saved ${state} state`,()=>{
    const r=fixture();r.resultSummary.coverageStatus=state;r.resultSummary.scaStatus=state;
    const top=visible(render(r));assert.ok(top.includes(summaryStateLabel(state)));
    assert.ok((top.match(new RegExp(`<code>${state}</code>`,'g'))||[]).length>=2);
  });
}

test('missing or unsupported summaries never synthesize candidate counts or policy',()=>{
  for(const summary of [undefined,{schemaVersion:999,title:'UNSUPPORTED_SAFE'}]){
    const r=fixture();r.resultSummary=summary;delete r.riskAssessment;delete r.coverage;delete r.sca;
    const html=render(r);
    assert.ok(html.includes('새 요약 기록이 없는 이력'));assert.ok(html.includes('미기록'));
    assert.ok(html.includes('<code>NOT_RECORDED</code>'));assert.ok(!html.includes('UNSUPPORTED_SAFE'));
    assert.ok(!html.includes('<dd>0건</dd>'));assert.ok(!html.includes('<code>READY</code>'));
  }
});

test('rendering preserves every existing fixture and input snapshot without mutation',()=>{
  for(const {result} of require('./summary-fixture.cjs')()){
    const before=JSON.stringify(result);render(result);assert.equal(JSON.stringify(result),before);
  }
});
