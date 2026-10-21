import type { SupabaseAnalysis } from '../types/supabaseAnalysis';
const labels: Record<string,string>={
  POLICY_STEP_BUDGET:'정책 작업량 예약 상한 · 남은 migration 미검사, 권한 결론 미확인',
  SQL_SOURCE_NOT_INSPECTED:'SQL 입력을 검사하지 못함',SOURCE_FILE_COUNT_LIMIT:'공통 파일 수 상한',SOURCE_TOTAL_CHAR_LIMIT:'공통 문자 수 상한',SOURCE_FILE_SIZE_LIMIT:'개별 파일 크기 상한',
  ENABLED:'RLS 활성화 선언',DISABLED:'RLS 비활성화 선언',DISABLED_BY_CREATE:'테이블 생성 시 RLS 비활성 상태',
  UID_COLUMN_EQUALITY:'현재 사용자 ID와 컬럼 일치 조건',AUTHENTICATION_ONLY:'로그인 여부 조건 · 소유권 확인 아님',
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
    <p>정책 파일 {snapshot.files.length}개 · 테이블 선언 {snapshot.tables.length}개 · 별도 검토 항목 {snapshot.findings.length}건</p>
    <p>저장소의 선언만 확인했습니다. 실제 운영 DB 적용·로그인 사용자·관리자 우회는 확인하지 않았으며, 항목이 없어도 안전을 보증하지 않습니다.</p>
    <p className="review-caution">기존 점수·배포 판단·해결 건수와 분리된 결과입니다. 로그인 허용과 데이터 소유권 제한은 다릅니다.</p>
    {!compact&&<>
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
