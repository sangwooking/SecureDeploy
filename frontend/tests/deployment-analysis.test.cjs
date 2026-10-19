const {test}=require('node:test');
const assert=require('node:assert/strict');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {DeploymentAnalysisSection}=require('./load-component.cjs')('DeploymentAnalysisSection');
const fixture=require('./deployment-fixture.cjs');
const render=(snapshot,compact=false)=>renderToStaticMarkup(React.createElement(DeploymentAnalysisSection,{snapshot,compact}));
test('configuration evidence is actionable and separate from deployment decision',()=>{
  const html=render(fixture());
  for(const s of ['compose.yaml:4','설정 선언 · 추가 확인 필요','어떻게 수정하나요?','수정 후 확인','NOT_COMPARED','점수·배포 판단·반드시 처리 건수에 합산하지 않습니다','값 미확인 1건'])assert.ok(html.includes(s),s);
  assert.equal((html.match(/<article /g)||[]).length,1);
});
test('legacy, absent, partial and failed inspections never certify safety',()=>{
  assert.ok(render(null).includes('기록이 없습니다')); assert.equal(render(null,true),'');
  const data=fixture();data.findings=[];data.files[0].status='PARSE_FAILED';
  assert.ok(render(data).includes('파싱 실패'));assert.ok(render(data).includes('안전하다는 뜻은 아닙니다'));
  assert.ok(render(data,true).includes('읽지 못한 파일 1개'));
});
test('Django environment hints and Wrangler document positions are honest',()=>{
  const data=fixture();data.files[0].format='WRANGLER';data.files[0].observations[0].scope='DEVELOPMENT_NAME_HINT_NOT_RUNTIME_PROOF';
  const html=render(data);for(const s of ['문서 단위','개발용 이름 단서','실제 적용 환경 미확인'])assert.ok(html.includes(s),s);
});
test('untrusted API strings are escaped, never rendered as source HTML',()=>{
  const data=fixture();data.findings[0].reason='<img src=x onerror=alert(1)>';
  const html=render(data);assert.ok(!html.includes('<img'));assert.ok(html.includes('&lt;img'));
});
