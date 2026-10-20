import type { JavaSqlSnapshot, AnalysisLocation } from '../types/serverAnalysis';

const statuses: Record<string, string> = { PARTIAL: '일부 경로 확인', UNAVAILABLE: '확인하지 못함', TIMEOUT: '분석 시간 초과',
  PARSED: '구문 파싱 성공', PARSE_FAILED: '구문 파싱 실패', LIMIT_EXCEEDED: '자원 제한', NOT_RUN: '미실행',
  INPUT_IN_QUERY: '요청 값이 SQL 명령문에 전달됨', STATIC_QUERY: 'SQL 문법에 요청 입력 전달 없음',
  PARAMETERIZED_QUERY: '정적 SQL과 값 바인딩 호출 관측', UNRESOLVED_QUERY: '값 전달 또는 검증 효과 미확인',
  RESOLVED_CALL: '타입과 구현체를 확인한 클래스 간 전달', DECLARED_QUERY_CONTRACT: '정적 쿼리 선언 확인',
  DERIVED_OPERATION_CONTRACT: '저장소 메서드 선언 확인', DECLARED_VALUE_BINDING: '정적 SQL 선언과 값 바인딩 확인',
  INPUT_SUBSTITUTION: '요청 입력의 SQL 문자열 치환 확인', UNKNOWN: '호출·SQL 구성 미확인',
  PARSED_DECLARATIONS: 'Mapper 선언 파싱 성공', NOT_INSPECTED: '선언을 검사하지 못함',
};
const statusText = (value: string) => statuses[value] ?? '지원 범위 밖이거나 확인이 필요한 상태';
const position = (l: AnalysisLocation) => `${l.filePath}:${l.line} · ${l.functionName}`;

export function JavaSqlAnalysisSection({ snapshot, compact = false }: { snapshot?: JavaSqlSnapshot | null; compact?: boolean }) {
  if (!snapshot) return compact ? null : <section className="analysis-coverage-brief"><h3>Java SQL 코드 흐름 검사</h3>
    <p>이 이력에는 Java SQL 흐름 기록이 없습니다. 과거 검사 범위를 추측하지 않습니다.</p></section>;
  const a = snapshot.analysis;
  if (a.status === 'NOT_APPLICABLE') return null;
  return <section className="analysis-coverage-brief" aria-label="Java SQL 코드 흐름 검사">
    <h3>Java SQL 코드 흐름 검사 · {statusText(a.status)}</h3>
    <p>별도 확인 후보 {snapshot.findings.length}건 · 기존 패턴 신호 연결 근거 {snapshot.legacyEvidence.length}건</p>
    <p className="review-caution">Spring/Servlet의 지원 경로만 확인했습니다. 항목 0건·파싱 성공은 전체 Java 코드가 안전하다는 뜻이 아닙니다.
      새 독립 후보는 기존 점수·배포 판단·해결 건수에 합산하지 않습니다. 구조적으로 정상임이 확인된 기존 경고만 제외합니다.</p>
    {!compact && <>
      {snapshot.findings.map(f => <article className="finding-card" key={f.findingId}>
        <h4>{f.title}</h4><p>배포 전 직접 확인 · 정적 전달 근거 (CWE-89)</p>
        <code className="finding-location">{position(f.location)}</code><p>{f.explanation}</p>
        <h5>어떻게 수정하나요?</h5><p>{f.recommendation}</p>
        <h5>수정 후 확인</h5><ul>{f.verificationSteps.map((s, i) => <li key={i}>{s}</li>)}</ul>
        <details className="technical-details"><summary>입력 전달 경로와 기술 정보</summary>
          <p>{f.ruleId} · {f.priority} · {f.comparisonPolicy}</p>
          <ol>{f.trace.map((l, i) => <li key={i}><code>{position(l)}</code></li>)}</ol>
        </details>
      </article>)}
      <details className="technical-details"><summary>Java 검사 범위와 SQL 호출 근거</summary>
        <p>{a.version} · 기존 정상 패턴 신호 제외 {snapshot.suppressedLegacyCount}건</p>
        <p>확인 가능한 타입·DI·유일한 구현체의 제한된 전달 근거입니다. 저장소 선언 확인은 실제 DB 실행이나 안전성 보증이 아닙니다. 외부 보호 계층·동적 SQL·전체 호출 그래프는 미확인입니다.</p>
        <ul>{a.files.slice(0, 20).map(f => <li key={f.filePath}>
          <code className="finding-location">{f.filePath}</code> · {statusText(f.parseStatus)}
          <p>진입점 {f.entrypoints} · 추적 함수 {f.functions} · SQL 호출 구문 {f.sqlCallSites} / 추적 {f.tracedCallSites}</p>
          <p>호출 구문 수는 이름 기반 후보이며, SQL 실행 확인 수와 다릅니다.</p>
          {!!f.limitations.length && <p>지원 경로 밖의 호출·구문 또는 자원 제한이 있습니다. 미확인 영역은 안전으로 판단하지 않습니다.</p>}
        </li>)}</ul>
        {!!a.dataAccess?.length && <details className="technical-details"><summary>클래스 간 전달과 저장소 선언 근거 ({a.dataAccess.length})</summary>
          <p>미확인은 안전이나 취약점 확정이 아닙니다. 동적 SQL·프록시 실행·외부 상속 구현은 별도 확인이 필요합니다.</p>
          <ul>{a.dataAccess.slice(0, 40).map((d, i) => <li key={i}>
            <code className="finding-location">{position(d.location)}</code>
            <p>{d.framework} · {d.operation} · {statusText(d.status)}</p>
            {d.declaration && <p>선언 위치: <code>{position(d.declaration)}</code></p>}
            {!!d.limitations.length && <p>추가 확인: {d.limitations.join(' · ')}</p>}
          </li>)}</ul>
          {a.dataAccess.length > 40 && <p>전체 {a.dataAccess.length}건 중 40건을 표시합니다.</p>}
        </details>}
        {a.files.length > 20 && <p>전체 {a.files.length}개 중 20개 파일을 표시합니다. 전체 범위는 검사 범위 기록을 함께 확인하세요.</p>}
        <ul>{a.uses.slice(0, 30).map((u, i) => <li key={i}><code>{position(u.location)}</code>
          <p>{statusText(u.kind)} · {u.api} · 값 바인딩 호출 관측 {u.bindingCalls}회</p>
          {!!u.limitations.length && <p>검증·변환·호출 경로를 확인하지 못한 부분이 있습니다.</p>}
        </li>)}</ul>
        {snapshot.legacyEvidence.length > 0 && <details className="technical-details"><summary>기존 경고와 연결된 실행 위치</summary>
          <ul>{snapshot.legacyEvidence.map((e, i) => <li key={i}><code>{e.filePath}:{e.line}</code>
            <ul>{e.executions.map((l, j) => <li key={j}><code>{position(l)}</code></li>)}</ul>
          </li>)}</ul>
          <p>같은 실행 위치로 확인된 중복 신호만 병합합니다. 서로 다른 실행 위험을 하나로 단정하지 않습니다.</p>
        </details>}
      </details>
    </>}
  </section>;
}
