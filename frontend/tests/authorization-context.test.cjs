const {test}=require('node:test');const assert=require('node:assert/strict');const React=require('react');const {renderToStaticMarkup}=require('react-dom/server');
const {AuthorizationContextDetails}=require('./load-component.cjs')('AuthorizationContextDetails');const fixture=require('./authorization-fixture.cjs');
const render=details=>renderToStaticMarkup(React.createElement(AuthorizationContextDetails,{details}));
test('login declaration and actual resource guards are separate with actionable locations',()=>{
  const html=render(fixture().details);
  for(const s of ['로그인 요구 선언 확인','객체 소유권 검사는 아님','app/views.py:5','app/views.py:8','소유자 일치 시 차단','두 사용자','실제 인증 설정·미들웨어'])assert.ok(html.includes(s),s);
});
test('public, global, unknown and object-check-called states never claim object safety',()=>{
  for(const authenticationStatus of ['DECLARED_PUBLIC','UNKNOWN']){
    const d=fixture().details;d.authenticationStatus=authenticationStatus;d.permissionSource='GLOBAL_CANDIDATE_ACTIVATION_UNKNOWN';d.accesses[0].conclusion='OBJECT_CHECK_CALLED_POLICY_UNKNOWN';d.objectAuthorizationStatus='NOT_ESTABLISHED';
    const html=render(d);for(const s of ['객체별 접근 권한을 판단하지 못함','활성 모듈·덮어쓰기 미확인','보호 효과 미확인'])assert.ok(html.includes(s),s);
  }
});
test('authorization metadata from API is escaped without rendering source markup',()=>{
  const d=fixture().details;d.accesses[0].location.filePath='<img src=x onerror=alert(1)>';
  const html=render(d);assert.ok(!html.includes('<img'));assert.ok(html.includes('&lt;img'));
});
