const {test}=require('node:test');
const assert=require('node:assert/strict');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const load=require('./load-component.cjs');
const render=(name,props)=>renderToStaticMarkup(React.createElement(load(name)[name],props));
test('summary puts actionable server priorities before the qualified reference score without changing data',()=>{
  const result=require('./result-fixture.cjs')(),before=JSON.stringify(result);
  const html=render('ReviewResultWorkspace',{result,view:'SUMMARY',onViewChange(){},statusActions:{updatingId:null,comments:{},onComment(){},onStatus(){}},reportActions:null,progress:null});
  assert.ok(html.indexOf('aria-label="확인할 문제"')<html.indexOf('검사 규칙 기준 참고 점수'));
  assert.ok(html.indexOf('가장 먼저 확인할 문제')<html.indexOf('검사 규칙 기준 참고 점수'));
  assert.ok(html.includes('배포 판단의 검사 범위 한계'));
  assert.ok(html.includes('전체 안전 점수가 아닙니다'));
  assert.equal(JSON.stringify(result),before);
});
test('Diff uses escaped text and preserves all patch bytes including trailing lines',()=>{
  const patch='@@ -1 +1 @@\n-secret\n+<script>not executable</script>\n';
  const html=render('PatchDiff',{patch});
  assert.ok(html.includes('diff-added'));assert.ok(html.includes('diff-removed'));assert.ok(html.includes('diff-hunk'));
  assert.ok(html.includes('&lt;script&gt;'));assert.ok(!html.includes('<script>'));
  const text=html.replace(/<[^>]+>/g,'').replace(/&lt;/g,'<').replace(/&gt;/g,'>');
  assert.equal(text,patch);
  assert.ok(html.includes('tabindex="0"'));
});
test('comparison keeps policy and uncertainty visible while moving raw context into disclosure',()=>{
  const result=require('./progress-fixture.cjs')(),before=JSON.stringify(result),html=render('ReviewProgressPanel',{result});
  assert.ok(html.indexOf('저장된 정책 판단')<html.indexOf('규칙 기반 참고 점수'));
  assert.ok(html.indexOf('aria-label="변화 분류"')<html.indexOf('class="comparison-context"'));
  assert.ok(html.indexOf('NOT_COMPARED')<html.indexOf('class="comparison-context"'));
  assert.ok(html.includes('비교한 분석·정책·파일 근거'));
  assert.equal(JSON.stringify(result),before);
});
test('unverified baseline and incomplete comparison messages are never hidden in technical context',()=>{
  const result=require('./progress-fixture.cjs')();
  result.comparison.message='baseline-not-comparable';
  result.comparison.workspaceScan={revision:1,originalReviewId:1,baselineVerified:false,files:[]};
  const html=render('ReviewProgressPanel',{result});
  assert.ok(html.indexOf('원본 동일성 미확인: 과거 Review')<html.indexOf('class="comparison-context"'));
  assert.ok(html.indexOf('baseline-not-comparable')<html.indexOf('class="comparison-context"'));
});
test('known local proposal capacity avoids unnecessary requests without altering server approval gates',()=>{
  const fs=require('node:fs'),path=require('node:path');
  const source=fs.readFileSync(path.join(__dirname,'../src/components/AiPatchPanel.tsx'),'utf8');
  assert.ok(source.indexOf('if(preparationLimitReached)')<source.indexOf('fixOption(workspace'));
  assert.ok(source.includes('!selected || !accepted || dirty'));
  assert.ok(source.includes('!!selected.flowFindingId&&!compatibilityAccepted'));
});
