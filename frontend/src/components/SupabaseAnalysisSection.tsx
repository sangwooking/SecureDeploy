import type { SupabaseAnalysis } from '../types/supabaseAnalysis';
const labels: Record<string,string>={
  REQUEST_CONTROLLED:'요청자가 제어할 수 있는 값',VERIFIED_USER_EVIDENCE:'검증 API 반환 ID와 중단 분기 근거 · 인증 성공 보장 아님',
  SESSION_UNVERIFIED:'세션 사용자 ID 참조 · 사용자 검증 미확인',SERVER_CONTROLLED:'정적으로 확인한 상수',
  STATIC_FIELDS:'정적 필드별 출처 기록',NO_PAYLOAD:'변경 데이터 없음',STATIC_FILTERS:'지원 필터 구문 확인 · 행 권한 보장 아님',
  FACTORY_CONFIGURATION_ABSENCE_THROW:'설정값 부재 시 중단하는 factory 분기 · 인증 검사 아님',
  CONFIRMED_POLICY_EVIDENCE:'저장소 정책에 사용자별 행 제한 근거가 있음',BROAD_ACCESS_REVIEW:'넓은 쓰기 허용 선언 · 공유 데이터인지 확인 필요',
  ADMIN_ACCESS_REVIEW:'관리자 Client 계약 · 앱 자체의 접근권한 확인 필요',PUBLIC_READ_DECLARATION:'공유 읽기 허용 선언 · 공개 의도 미확인',
  SESSION_REFERENCE_UNVERIFIED:'쿠키·세션 참조 · 사용자 검증은 미확인',SESSION_READ_UNVERIFIED:'세션 읽기 관찰 · 사용자 검증 아님',
  IDENTITY_VERIFICATION_CALL_OBSERVED:'사용자 검증 API 호출 관찰 · 성공·적용은 미확인',USER_JWT_WRAPPER_DECLARATION:'공식 wrapper의 사용자 JWT 검증 선언',
  IDENTITY_RESULT_GUARD_OBSERVED:'사용자 정보가 없을 때 중단하는 분기 관찰 · 인증 성공 보장 아님',
  SESSION_AND_AUTH_HEADERS_UNKNOWN:'개별 사용자 세션·인증 헤더 적용 미확인',OPTIONS_OR_AUTH_OVERRIDE_NOT_EVALUATED:'Client 옵션·인증 헤더 문맥 미확인',
  WRAPPER_CALLER_MODE_NOT_USER_PROOF:'호출 자격 선언 · 개별 사용자 확인의 증거 아님',
  CLIENT_POLICY_LINK_BUDGET_LIMIT:'Client·정책 연결 작업 상한 · 나머지 연결 미검사',CLIENT_POLICY_EVIDENCE_OUTPUT_LIMIT:'연결 근거 출력 상한 · 나머지 연결 미검사',
  SERVER_CLIENT_CONTRACT:'관리자 Client 제공 계약 · 실제 운영 DB 역할 미확인',PUBLIC_KEY_FORMAT_HINT:'공개용 키 형식 단서 · 실제 키 검증 없음',SERVER_KEY_FORMAT_HINT:'서버용 키 형식 단서 · 실제 권한 검증 없음',
  POLICY_STEP_BUDGET:'정책 작업량 예약 상한 · 남은 migration 미검사, 권한 결론 미확인',
  CLIENT_STEP_BUDGET:'Client 선언 작업량 예약 상한',CLIENT_AST_BUDGET_LIMIT:'Client 선언 분석의 실행 예산 부족',
  SQL_SOURCE_NOT_INSPECTED:'SQL 입력을 검사하지 못함',SOURCE_FILE_COUNT_LIMIT:'공통 파일 수 상한',SOURCE_TOTAL_CHAR_LIMIT:'공통 문자 수 상한',SOURCE_FILE_SIZE_LIMIT:'개별 파일 크기 상한',
  ENABLED:'RLS 활성화 선언',DISABLED:'RLS 비활성화 선언',DISABLED_BY_CREATE:'테이블 생성 시 RLS 비활성 상태',
  UID_COLUMN_EQUALITY:'현재 사용자 ID와 컬럼 일치 조건',AUTHENTICATION_ONLY:'로그인 여부 조건 · 소유권 확인 아님',
  UPDATE_NEW_ROW_UNRESTRICTED:'UPDATE 변경 후 행의 사용자별 제한 미확인 · 기존 행 조건만 확인',
  UPDATE_EXISTING_ROWS_UNRESTRICTED:'UPDATE 기존 행의 사용자별 제한 미확인 · 변경 후 행 조건만 확인',
  COLUMN_FILTER:'행의 컬럼 조건 · 사용자 소유권 확인 아님',
  ALLOW:'행 제한 없는 조건',DENY:'선언상 허용 경로 없음',UNKNOWN:'확인 불가',NOT_ESTABLISHED:'명시적 GRANT 미확인',
  EXPLICIT_GRANT:'명시적 GRANT 확인',CLIENT_DECLARATION_LINKED:'Client 생성 선언 연결',CLIENT_ORIGIN_UNKNOWN:'Client 출처 미확인',
  PUBLIC_KEY_NAME_HINT:'공개용 키 이름 단서 · 실제 키 미확인',SERVER_KEY_NAME_HINT:'서버용 키 이름 단서 · 실제 DB 역할 미확인',
  ENVIRONMENT_REFERENCE_UNKNOWN:'환경값 참조 · 키 종류 미확인',TABLE_DECLARATION_FOUND:'테이블 선언 연결',POLICY_CONTEXT_MISSING:'정책 문맥 미확인',
  PARSED:'지원 선언 구문 확인',PARTIAL:'일부 범위 확인',PARSE_FAILED:'파일 파싱 실패',LIMIT_EXCEEDED:'자원 제한',NOT_RUN:'미검사',
};
const text=(v:string)=>labels[v]??v;
export function SupabaseAnalysisSection({snapshot,compact=false}:{snapshot?:SupabaseAnalysis|null;compact?:boolean}){
  if(!snapshot)return compact?null:<section className="analysis-coverage-brief"><h3>Supabase 데이터 접근 검사</h3><p>이 이력에는 RLS 검사 기록이 없습니다. 과거 상태를 추측하지 않습니다.</p></section>;
  if(snapshot.status==='NOT_APPLICABLE')return null;
  return <section className={compact?'analysis-coverage-brief':'server-analysis-section'} aria-label="Supabase 데이터 접근 검사">
    <h3>Supabase 데이터 접근 검사</h3>
    <p>정책 파일 {snapshot.files.length}개 · 테이블 선언 {snapshot.tables.length}개 · 정책 검토 항목 {snapshot.findings.length}건</p>
    <p>앱 접근 {snapshot.accesses.length}곳 · 연결 근거 기록 {snapshot.accesses.filter(a=>a.authorizationEvidence).length}곳 · 권한 문맥 미확인 {snapshot.accesses.filter(a=>a.authorizationEvidence?.state==='UNKNOWN').length}곳 · 연결 미검사 또는 이전 기록 없음 {snapshot.accesses.filter(a=>!a.authorizationEvidence).length}곳</p>
    <p>저장소의 선언만 확인했습니다. 실제 운영 DB 적용·로그인 사용자·관리자 우회는 확인하지 않았으며, 항목이 없어도 안전을 보증하지 않습니다.</p>
    <p className="review-caution">기존 점수·배포 판단·해결 건수와 분리된 결과입니다. 로그인 허용과 데이터 소유권 제한은 다릅니다.</p>
    {!compact&&<>
      {snapshot.budgetUsage&&<details className="coverage-details"><summary>분석 실행 예산</summary>
        <p>공통 단계 {snapshot.budgetUsage.STEPS_USED} / {snapshot.budgetUsage.STEPS_LIMIT} · 정책 {snapshot.budgetUsage.STEPS_POLICY} · Client 선언 {snapshot.budgetUsage.STEPS_CLIENT} · 진입점 확인 {snapshot.budgetUsage.STEPS_ENTRY_DISCOVERY} · 흐름 추적 {snapshot.budgetUsage.STEPS_FLOW}</p>
        <p>파일 선택·파싱과 실행 단계는 다릅니다. 일부 분석이 중단되어도 다른 단계의 확인된 근거는 별도로 보존합니다. 선언은 실제 실행이나 권한 검증의 증거가 아닙니다.</p>
      </details>}
      <div className="vulnerability-list">{snapshot.findings.map(f=><article className="vulnerability-item action-finding" key={f.findingId}>
        <span className="risk-badge risk-review_required">사용자 접근권한 · 추가 확인 필요</span><h4>{f.title}</h4>
        <p className="finding-location">{f.location.filePath}:{f.location.line} · {f.table}</p>
        <p>역할: {f.roles.join(', ')} · 작업: {f.operations.join(', ')}</p><p>{f.reason}</p>
        <h4>어떻게 수정하나요?</h4><p>{f.recommendation}</p><h4>수정 후 확인</h4><ol>{f.verificationSteps.map(s=><li key={s}>{s}</li>)}</ol>
        <details className="technical-details"><summary>정책 근거와 한계</summary><p>{f.ruleId} · {f.priority} · {f.comparisonPolicy}</p>
          {f.evidenceLocations.map((l,i)=><p className="finding-location" key={i}>{l.filePath}:{l.line}</p>)}
          <p>공유 데이터의 의도와 실제 공격 가능성은 미확인입니다.</p></details>
      </article>)}</div>
      <details className="coverage-details"><summary>테이블별 작업·정책 선언 ({snapshot.tables.length})</summary>
        {snapshot.tables.map(t=><details key={t.scope+t.table} className="technical-details"><summary>{t.table} · {text(t.rls)}</summary>
          <p className="finding-location">{t.location.filePath}:{t.location.line}</p>
          <ul>{t.operations.map(o=><li key={o.role+o.operation}>{o.role} · {o.operation}: {text(o.state)} · {text(o.grant)}
            <span> · 기존 행: {text(o.using)} / 새 행: {text(o.check)}{o.columns.length?` · 비교 컬럼: ${o.columns.join(', ')}`:''}</span></li>)}</ul>
          {t.policies.map((p,i)=><p key={i}>{p.name} · {p.mode} · {p.command} · {p.roles.join(', ')} · {p.location.filePath}:{p.location.line}</p>)}
          <p>컬럼 비교는 선언 근거입니다. 실제 소유권 모델과 역할 상속은 검증하지 않았습니다.</p>
        </details>)}
      </details>
      <details className="coverage-details"><summary>앱의 데이터 접근 선언 ({snapshot.accesses.length})</summary>
        {snapshot.accesses.map((a,i)=><div key={i}><p className="finding-location">{a.location.filePath}:{a.location.line}</p>
          <p>{a.table} · {a.operation} · {text(a.clientStatus)} · {text(a.keySource)} · {text(a.policyStatus)}</p>
          {a.writeEvidence?<details className="technical-details"><summary>쓰기 데이터와 대상 행의 값 출처</summary>
            <p className="finding-location">쓰기 위치: {a.writeEvidence.operationLocation.filePath}:{a.writeEvidence.operationLocation.line}</p>
            <h4>변경할 데이터</h4><p>{text(a.writeEvidence.dataStatus)}</p>
            {a.writeEvidence.dataFields.map((v,j)=><div key={'d'+j}><p>{v.name} · {text(v.source)}</p><p className="finding-location">{v.location.filePath}:{v.location.line}</p>
              {v.sourceLocations.map((l,k)=><p className="finding-location" key={k}>값 출처: {l.filePath}:{l.line}</p>)}</div>)}
            <h4>기존 행을 선택하는 필터</h4><p>{a.writeEvidence.filterStatus==='STATIC_FILTERS'&&!a.writeEvidence.filters.length?'이 호출 체인에서 행 필터가 관찰되지 않았습니다.':text(a.writeEvidence.filterStatus)}</p>
            {a.writeEvidence.filters.map((v,j)=><div key={'f'+j}><p>{v.name} · {v.operator} · {text(v.source)}</p><p className="finding-location">{v.location.filePath}:{v.location.line}</p>
              {v.sourceLocations.map((l,k)=><p className="finding-location" key={k}>값 출처: {l.filePath}:{l.line}</p>)}</div>)}
            <p>값의 출처만 확인했습니다. 사용자 입력 사용 자체는 취약점이 아니며, 필터나 사용자 ID가 있어도 실제 소유권·운영 DB 보호를 보증하지 않습니다.</p>
            <p>이 쓰기 위치와 아래 연결된 정책의 USING·WITH CHECK를 함께 검토하세요. 사용자 전용 데이터라면 격리 환경에서 사용자 A·B의 생성·변경·삭제와 소유자 변경을 각각 확인한 뒤 재검사하세요.</p>
            <details><summary>미확인 사유 코드</summary><ul>{[...new Set([...a.writeEvidence.limitations,...a.writeEvidence.dataFields.flatMap(v=>v.limitations),...a.writeEvidence.filters.flatMap(v=>v.limitations)])].map(l=><li key={l}>{l}</li>)}</ul></details>
          </details>:['INSERT','UPDATE','DELETE'].includes(a.operation)&&<p>쓰기 값·행 필터의 출처는 미검사이거나 이전 이력에 기록되지 않았습니다. 안전으로 판단하지 않습니다.</p>}
          {a.authorizationEvidence?<>
            <p>{text(a.authorizationEvidence.state)} · {text(a.authorizationEvidence.authStatus)}</p>
            <p>API 키와 로그인 사용자는 다릅니다. 실제 DB 역할과 운영 정책 적용은 확인하지 않았습니다.</p>
            <p>연결된 정책은 같은 저장소의 선언입니다. Client의 실제 접속 프로젝트와 일치하는지는 확인하지 않았습니다.</p>
            <details className="technical-details"><summary>Client·인증·정책 연결 근거</summary>
              {a.authorizationEvidence.enclosingFunction&&<p className="finding-location">포함된 함수: {a.authorizationEvidence.enclosingFunction.filePath}:{a.authorizationEvidence.enclosingFunction.line} · 요청 실행 증명 아님</p>}
              {a.authorizationEvidence.clientTrace.map((l,j)=><p className="finding-location" key={'c'+j}>Client: {l.filePath}:{l.line}{l.kind==='FACTORY_CONFIGURATION_ABSENCE_THROW'&&<> · {text(l.kind)}</>}</p>)}
              {a.authorizationEvidence.requestEntry&&<p className="finding-location">Next.js 요청·서버 함수 선언: {a.authorizationEvidence.requestEntry.filePath}:{a.authorizationEvidence.requestEntry.line} · 같은 함수 안의 접근이며 실제 호출 여부는 미확인</p>}
              {a.authorizationEvidence.authChecks.map((c,j)=><div key={'a'+j}><p className="finding-location">{c.method}: {c.location.filePath}:{c.location.line} · {text(c.status)}</p>
                {c.resultEvidence&&<><p>{text(c.resultEvidence.status)}</p><p className="finding-location">중단 분기: {c.resultEvidence.guardLocation.filePath}:{c.resultEvidence.guardLocation.line}</p>
                  {c.resultEvidence.userIdFilters.map((l,k)=><p className="finding-location" key={k}>반환된 사용자 ID를 사용한 필터: {l.filePath}:{l.line} · DB 소유권 검증 보장 아님</p>)}
                </>}
              </div>)}
              {a.authorizationEvidence.policyLocations.map((l,j)=><p className="finding-location" key={'p'+j}>정책: {l.filePath}:{l.line}</p>)}
              {a.authorizationEvidence.filterLocations.map((l,j)=><p className="finding-location" key={'f'+j}>앱 필터: {l.filePath}:{l.line} · DB 권한 검사 보장 아님</p>)}
              <p>{a.authorizationEvidence.clientContract} · {a.authorizationEvidence.roleEvidence} · DB 역할: {text(a.authorizationEvidence.effectiveRole)}</p>
              <ul>{a.authorizationEvidence.policyStates.map((s,j)=><li key={j}>{s}</li>)}</ul>
              <p>이 호출과 Client 생성·정책 파일을 함께 검토하세요. 허가된 격리 환경에서 사용자 A·B 및 익명의 조회·생성·수정·삭제를 각각 테스트한 뒤 재검사하세요.</p>
            </details>
          </>:<p>이 연결의 권한 근거는 미검사이거나 이전 이력에 기록되지 않았습니다. 안전으로 판단하지 않습니다.</p>}
          <p>호출 구문이지 실행·인증 성공의 증거는 아닙니다.</p></div>)}
      </details>
      <details className="coverage-details"><summary>Client 생성과 키 출처 단서 ({snapshot.clients.length})</summary>
        {snapshot.clients.map((c,i)=><div key={i}><p className="finding-location">{c.location.filePath}:{c.location.line}</p><p>{text(c.keySource)}</p>
          <p>실제 키·DB 역할·사용자 인증은 확인하지 않았습니다. 키 이름만으로 관리자 우회를 확정하지 않습니다.</p>
          <details className="technical-details"><summary>인증 문맥 한계</summary><p>{c.authContext}</p></details></div>)}
      </details>
      <details className="coverage-details"><summary>검사한 SQL과 미확인 범위 ({snapshot.files.length})</summary>
        {snapshot.files.map((f,i)=><p className="finding-location" key={i}>{f.filePath} · {text(f.status)} · 선언문 {f.statements}개
          {f.limitations.length>0&&<span> · {f.limitations.map(text).join(' · ')}</span>}</p>)}
        <p>미지원 SQL·누락 파일·순서 불명확·자원 제한은 안전으로 처리하지 않습니다. 정책 파일이 없어도 운영 DB에 정책이 없다고 확정하지 않습니다.</p>
        <p>{snapshot.analyzerVersion} · {snapshot.status}</p>
        <details className="technical-details"><summary>미확인 사유 코드</summary><ul>{snapshot.limitations.map((l,i)=><li key={i}>{text(l)}</li>)}</ul></details>
      </details>
    </>}
  </section>;
}
