const {test}=require('node:test'),assert=require('node:assert/strict'),React=require('react'),{renderToStaticMarkup}=require('react-dom/server');
const {DependencyAiAdvicePanel}=require('./load-component.cjs')('DependencyAiAdvicePanel');
test('disabled AI preserves grounded guidance and never presents generated or applied changes',()=>{
 const input={reviewId:1,evidence:{reviewId:1,evidenceHash:'hash',plans:[]}};const before=JSON.stringify(input);const html=renderToStaticMarkup(React.createElement(DependencyAiAdvicePanel,input));
 assert.ok(html.includes('AI Provider가 비활성화'));assert.ok(html.includes('기존 근거 기반 한국어 안내'));assert.ok(html.includes('항목이 없습니다'));assert.ok(!html.includes('응답 검증 통과 · 수정 미적용'));assert.equal(JSON.stringify(input),before);
});
test('eligible plan identifiers are escaped and preparation does not imply transmission consent',()=>{
 const html=renderToStaticMarkup(React.createElement(DependencyAiAdvicePanel,{reviewId:1,evidence:{reviewId:1,evidenceHash:'hash',plans:[{ecosystem:'NPM',packageManagerEvidence:'NPM_LOCK_OBSERVED_VERSION_UNVERIFIED',sameMajorCandidates:['7.30.1'],locations:[{confirmed:true}],packageName:'<script>fixture</script>',lockedVersion:'7.29.1',advisoryId:'GHSA-test'}]}}));
 assert.ok(!html.includes('<script>'));assert.ok(html.includes('&lt;script&gt;'));assert.ok(html.includes('AI 전송 범위 확인'));assert.ok(!html.includes('동의한 근거로 AI 수정 방향 생성'));
});
