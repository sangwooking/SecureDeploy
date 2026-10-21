const {test}=require('node:test');const assert=require('node:assert/strict');const React=require('react');const {renderToStaticMarkup}=require('react-dom/server');
const {SupabaseAnalysisSection}=require('./load-component.cjs')('SupabaseAnalysisSection');
const fixture=require('./supabase-fixture.cjs');
const render=snapshot=>renderToStaticMarkup(React.createElement(SupabaseAnalysisSection,{snapshot}));
test('RLS findings explain users, operations, declaration evidence and safe local verification',()=>{
 const h=render(fixture());for(const s of ['사용자별 수정 권한','authenticated','UPDATE','NOT_COMPARED','USING','WITH CHECK','사용자 A·B','운영 DB','점수·배포 판단'])assert.ok(h.includes(s),s);
});
test('authentication, key hints, ownership conditions and missing runtime facts remain separate',()=>{
 const f=fixture();f.tables[0].operations[0].state='AUTHENTICATION_ONLY';const h=render(f);
 for(const s of ['로그인 여부 조건 · 소유권 확인 아님','서버용 키 이름 단서','실제 DB 역할 미확인','Client 출처 미확인'])assert.ok(h.includes(s),s);
 assert.ok(!h.includes('SERVICE_ROLE_KEY'));assert.ok(!h.includes('sb_secret_'));
});
test('legacy, absent policies and parse failures cannot be rendered as a safe database',()=>{
 assert.ok(render(null).includes('검사 기록이 없습니다'));const f=fixture();f.tables=[];f.findings=[];f.files[0].status='PARSE_FAILED';
 const h=render(f);assert.ok(h.includes('파일 파싱 실패'));assert.ok(h.includes('안전을 보증하지'));assert.ok(h.includes('정책이 없다고 확정하지'));
});
test('untrusted table, policy and path metadata is escaped rather than rendered',()=>{
 const f=fixture();f.tables[0].table='<img src=x>';f.findings[0].title='<script>malicious</script>';const h=render(f);
 assert.ok(!h.includes('<img'));assert.ok(!h.includes('<script>'));assert.ok(h.includes('&lt;img'));
});
