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
test('execution budgets are distinct from selected files and incomplete inspection is not safety',()=>{
 const f=fixture();f.budgetUsage={STEPS_USED:100000,STEPS_LIMIT:100000,STEPS_POLICY:25081,STEPS_CLIENT:1863,STEPS_ENTRY_DISCOVERY:25454,STEPS_FLOW:47602};
 const h=render(f);
 for(const s of ['분석 실행 예산','100000 / 100000','Client 선언 1863','파일 선택·파싱과 실행 단계는 다릅니다','안전을 보증하지'])assert.ok(h.includes(s),s);
 assert.ok(!render(fixture()).includes('분석 실행 예산'));
});
test('policy evidence, identity API observations and unknown runtime roles are separate',()=>{
 const f=fixture(),l=f.accesses[0].location;
 f.accesses[0].authorizationEvidence={state:'CONFIRMED_POLICY_EVIDENCE',clientContract:'SUPABASE_SSR_SERVER',authStatus:'IDENTITY_VERIFICATION_CALL_OBSERVED',effectiveRole:'UNKNOWN',roleEvidence:'PUBLIC_KEY_NAME_HINT',
  authChecks:[{method:'getUser',status:'IDENTITY_VERIFICATION_CALL_OBSERVED',location:l}],clientTrace:[l],policyLocations:[f.tables[0].location],filterLocations:[],enclosingFunction:l,policyStates:['authenticated:UPDATE:UID_COLUMN_EQUALITY'],limitations:[]};
 const h=render(f);
 for(const s of ['사용자별 행 제한 근거','성공·적용은 미확인','실제 DB 역할','getUser','Client·인증·정책 연결 근거','사용자 A·B'])assert.ok(h.includes(s),s);
 assert.ok(render(fixture()).includes('이 연결의 권한 근거는 미검사'));
});
test('local result guards and Next declarations are not rendered as successful authentication',()=>{
 const f=fixture(),l=f.accesses[0].location;
 f.accesses[0].authorizationEvidence={state:'UNKNOWN',clientContract:'SUPABASE_SSR_SERVER',authStatus:'IDENTITY_VERIFICATION_CALL_OBSERVED',effectiveRole:'UNKNOWN',roleEvidence:'UNKNOWN',
 authChecks:[{method:'getUser',status:'IDENTITY_VERIFICATION_CALL_OBSERVED',location:l,resultEvidence:{status:'IDENTITY_RESULT_GUARD_OBSERVED',guardLocation:l,userIdFilters:[l],limitations:[]}}],
 clientTrace:[],policyLocations:[],filterLocations:[],policyStates:[],limitations:[],requestEntry:l};
 const h=render(f);
 for(const s of ['중단 분기','실제 호출 여부는 미확인','DB 소유권 검증 보장 아님','반환된 사용자 ID'])assert.ok(h.includes(s),s);
});
test('UPDATE old and new row restrictions are shown separately without promising database authorization',()=>{
 for(const [state,label]of [['UPDATE_NEW_ROW_UNRESTRICTED','변경 후 행의 사용자별 제한 미확인'],['UPDATE_EXISTING_ROWS_UNRESTRICTED','기존 행의 사용자별 제한 미확인']]){
  const f=fixture();f.tables[0].operations[0].state=state;const h=render(f);
  assert.ok(h.includes(label));assert.ok(h.includes('운영 DB'));assert.ok(h.includes('NOT_COMPARED'));
 }
});
test('configuration absence exits in client factories are not authentication guards',()=>{
 const f=fixture(),l=f.accesses[0].location;
 f.accesses[0].authorizationEvidence={state:'UNKNOWN',clientContract:'SUPABASE_JS_CREATE_CLIENT',authStatus:'SESSION_AND_AUTH_HEADERS_UNKNOWN',effectiveRole:'UNKNOWN',roleEvidence:'UNKNOWN',
 authChecks:[],clientTrace:[{...l,kind:'FACTORY_CONFIGURATION_ABSENCE_THROW'}],policyLocations:[],filterLocations:[],policyStates:[],limitations:[]};
 const h=render(f);assert.ok(h.includes('설정값 부재 시 중단하는 factory 분기 · 인증 검사 아님'));
});
test('write fields and existing-row filters expose distinct origins without promising authentication',()=>{
 const f=fixture(),l=f.accesses[0].location;
 f.accesses[0].writeEvidence={status:'LOCAL_VALUE_ORIGIN_EVIDENCE',operationLocation:l,dataStatus:'STATIC_FIELDS',
 dataFields:[{name:'title',operator:'field',location:l,source:'REQUEST_CONTROLLED',sourceLocations:[l],limitations:[]}],filterStatus:'STATIC_FILTERS',
 filters:[{name:'user_id',operator:'eq',location:l,source:'VERIFIED_USER_EVIDENCE',sourceLocations:[l],limitations:[]}],limitations:[]};
 const h=render(f);
 for(const s of ['쓰기 데이터와 대상 행의 값 출처','변경할 데이터','기존 행을 선택하는 필터','요청자가 제어할 수 있는 값','인증 성공 보장 아님','사용자 A·B','title','user_id'])assert.ok(h.includes(s),s);
 assert.ok(!h.includes('자동 수정안 만들기'));assert.ok(render(fixture()).includes('쓰기 값·행 필터의 출처는 미검사'));
});
