const {test}=require('node:test');const assert=require('node:assert/strict');const React=require('react');const {renderToStaticMarkup}=require('react-dom/server');
const {TokenSecurityDetails}=require('./load-component.cjs')('TokenSecurityDetails');
const use={operation:'DECODE',location:{filePath:'api/views.py',line:8,functionName:'endpoint'},signatureStatus:'EXPLICITLY_DISABLED',keySource:'UNKNOWN',usageStatus:'ACCESS_REJECTION_BRANCH',trace:[],limitations:['EXTERNAL_TOKEN_VALIDATION_NOT_VERIFIED']};
const render=uses=>renderToStaticMarkup(React.createElement(TokenSecurityDetails,{uses}));
test('token signature bypass and security decision are separate from library assurance',()=>{const html=render([use]);for(const s of ['서명 검증 생략','접근 거부 조건','api/views.py:8','실제 설치 라이브러리','변조·만료 토큰'])assert.ok(html.includes(s),s)});
test('missing and zero evidence are not safe results',()=>{assert.ok(render(null).includes('기록되지'));assert.ok(render([]).includes('안전하다는 의미는 아닙니다'));});
test('environment and default verification never guarantee safety and paths are escaped',()=>{const html=render([{...use,signatureStatus:'DEFAULT_OR_ENABLED_CALL',keySource:'ENVIRONMENT_REFERENCE',location:{...use.location,filePath:'<img src=x>'}}]);assert.ok(html.includes('검증 성공 보증 아님'));assert.ok(html.includes('키 품질'));assert.ok(!html.includes('<img'));});
test('unconnected token candidates never receive SQL guidance titles',()=>{
  const {ServerAnalysisSection}=require('./load-component.cjs')('ServerAnalysisSection');
  const snapshot=require('./server-analysis-fixture.cjs')();snapshot.validatedFindings=[];snapshot.findings[0].ruleId='PY_JWT_UNVERIFIED_ACCESS_DECISION';
  const html=renderToStaticMarkup(React.createElement(ServerAnalysisSection,{snapshot}));
  assert.ok(html.includes('토큰을 신뢰하기 전 서명 검증'));assert.ok(!html.includes('요청 값이 데이터베이스 쿼리에 들어갑니다'));
});
