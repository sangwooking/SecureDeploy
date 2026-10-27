const {test}=require('node:test');const assert=require('node:assert/strict');const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {ServerAnalysisSection}=require('./load-component.cjs')('ServerAnalysisSection');
const fixture=require('./server-analysis-fixture.cjs');
test('web policy candidates have distinct titles and no unsupported automatic patches',()=>{
 for(const [rule,title]of [['JS_CORS_CREDENTIAL_REFLECTION','CORS'],['JS_SESSION_COOKIE_ATTRIBUTE_REVIEW','쿠키']]){
  const data=fixture();data.validatedFindings=[];data.findings[0].ruleId=rule;
  const html=renderToStaticMarkup(React.createElement(ServerAnalysisSection,{snapshot:data,onEditFile:()=>{}}));
  assert.ok(html.includes(title));assert.ok(!html.includes('자동 수정안 만들기'));assert.ok(!html.includes('AI 수정안 만들기'));
  assert.ok(html.includes('전체 코드가 안전하다는 의미는 아닙니다'));
 }
});
