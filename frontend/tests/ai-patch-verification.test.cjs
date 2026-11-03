const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createElement}=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {AiPatchVerification}=require('./load-component.cjs')('AiPatchVerification');

test('unsupported model claims stay outside the server verification section',()=>{
  const claim='삭제한 적 없는 admin.ts가 삭제되어 모든 API가 안전합니다.';
  const selected={state:'PROPOSED',provider:{origin:'OPENAI'},explanation:claim,
    verificationSteps:[],limitations:[],diff:'-credential\n+ready',
    plan:{},context:{removedFields:['credential'],preservedFields:['ready']}};
  const html=renderToStaticMarkup(createElement(AiPatchVerification,{selected,deterministic:false}));
  assert.match(html,/<details><summary>AI 수정 조언 · 사실 여부 미검증<\/summary>/);
  assert.ok(html.includes(claim));
  const verified=html.match(/<section aria-label="서버 변경 검증 결과">([\s\S]+)<\/section>/)[1];
  assert.ok(!verified.includes(claim));
  assert.match(verified,/제거 대상 credential 및 보존 대상 ready/);
  assert.match(verified,/실제 실행 동작과 API 호환성은 이 검사에 포함되지/);
});

test('provider refusal cannot display a verified change without a diff',()=>{
  const selected={state:'NEEDS_REVIEW',provider:{origin:'MOCK'},explanation:'모델이 거부했습니다.',
    verificationSteps:[],limitations:[]};
  const html=renderToStaticMarkup(createElement(AiPatchVerification,{selected,deterministic:false}));
  assert.match(html,/모델이 거부했습니다/);
  assert.doesNotMatch(html,/서버 변경 검증 결과/);
});
