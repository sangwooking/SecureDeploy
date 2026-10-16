import { useState } from 'react';
import type { AnalysisLocation, ServerAnalysisSnapshot } from '../types/serverAnalysis';

const labels: Record<string, string> = {
  COMPLETE: '제한된 범위 확인 완료', PARTIAL: '일부만 확인', NOT_APPLICABLE: '대상 파일 없음',
  UNAVAILABLE: '분석하지 못함', TIMEOUT: '분석 시간 초과', DISABLED: '실행하지 않음',
  PARSED: '구문 확인', PARSE_FAILED: '구문 파싱 실패', LIMIT_EXCEEDED: '크기·자원 제한', NOT_RUN: '미실행',
  SUPPORTED_FLOW_ANALYZED: '지원하는 값 전달 경로 확인', NOT_SUPPORTED: '지원되는 서버 흐름 아님',
  INPUT_IN_QUERY: '요청 값이 쿼리 문자열에 포함', PARAMETERIZED_QUERY: '정적 쿼리와 값 바인딩 확인',
  STATIC_QUERY: '정적인 쿼리 구성 확인', UNRESOLVED_QUERY: '쿼리 구성 확인 불가',
  QUERY_PARAMETER: 'URL에서 받은 값', REQUEST_BODY: '요청 본문', ROUTE_PARAMETER: '경로에서 받은 값',
  REQUEST_URL: '요청 URL', VARIABLE: '변수로 전달', ASSIGNMENT: '변수에 대입', FUNCTION_ARGUMENT: '함수 인자로 전달',
  D1_PREPARE: '데이터베이스 쿼리 구성', VALUE_BINDING: '값 매개변수 바인딩',
  SQL_STRING_CONSTRUCTION: '쿼리에 전달할 문자열 구성', SQL_EXECUTION_CALL: '쿼리 실행 호출',
  LITERAL_IDENTIFIER_ALLOWLIST: '고정된 식별자 허용 목록과 분기 확인',
  SCHEDULED_ENTRY_NOT_SUPPORTED: '예약 실행 진입점은 현재 추적 대상이 아님',
  LOGIN_CONTEXT_REFERENCE: '로그인 문맥 참조', CONDITIONAL_CHECK: '조건 분기',
  EARLY_EXIT_BRANCH_PRESENT: '처리를 중단하는 분기', NUMERIC_CONVERSION: '숫자 변환',
  VALIDATION_EXPRESSION_PRESENT: '입력 검사 표현식',
  CALL_DEPTH_EXCEEDED: '함수 추적 깊이 또는 순환 호출 제한', CALL_TARGET_UNRESOLVED: '호출 대상이나 처리 내용 확인 불가',
  LOOP_FLOW_PARTIAL: '반복문 전체 경로 미검증', EXCEPTION_FLOW_PARTIAL: '예외 처리 전체 경로 미검증',
  SWITCH_FLOW_PARTIAL: '분기 간 전체 경로 미검증', CALLBACK_FLOW_UNSUPPORTED: '콜백 내부 값 전달 미지원',
  UNREACHED_FUNCTIONS_NOT_ANALYZED: '진입점에서 연결하지 못한 함수는 미검사',
  NO_SUPPORTED_SERVER_ENTRY_OR_CALL: '지원하는 서버 진입점 또는 함수 호출을 확인하지 못함',
  REACT_UI_NOT_SERVER_AUTHORIZATION: 'React 화면의 제한을 서버 권한 검사로 취급하지 않음',
  SOURCE_LIMIT_EXCEEDED: '파일 크기·개수·전체 텍스트 제한', ANALYSIS_BUDGET_EXCEEDED: '시간·작업량 제한',
  INVALID_SYNTAX: '지원 파서에서 구문을 읽지 못함', QUERY_HAS_UNRESOLVED_VALUES: '쿼리 값의 일부 처리 과정 미확인',
  QUERY_CONSTRUCTION_NOT_EXPLOIT_PROOF: '쿼리 구성 근거이며 실제 공격 성공을 확인한 것은 아님',
  BIND_DOES_NOT_REWRITE_QUERY: '바인딩도 있지만 이미 결합된 쿼리 문자열은 바꾸지 않음',
  PATH_FEASIBILITY_NOT_VERIFIED: '실행 조건과 실제 공격 가능성은 별도 확인 필요',
  EXECUTION_PATH_PARTIAL: '실행 호출 주변의 제어 흐름을 일부만 확인함',
  TRACE_DETAILS_TRUNCATED: '전달 경로가 길어 일부 중간 단계를 생략함',
  PREPARE_CALLS_OUTSIDE_TRACED_FLOW: 'prepare 호출 구문 중 확인한 서버 경로에 연결되지 않은 부분이 있음',
};
const text = (value: string) => labels[value] ?? (/^[A-Z_]+$/.test(value) ? '지원 범위 밖이거나 추가 확인이 필요한 처리' : value);
const location = (value: AnalysisLocation) => `${value.filePath}:${value.line} · ${value.functionName}`;

export function ServerAnalysisSection({ snapshot, compact = false }: { snapshot?: ServerAnalysisSnapshot | null; compact?: boolean }) {
  const [page, setPage] = useState(0);
  if (!snapshot) return compact ? null : <section className="analysis-coverage-brief"><h3>서버 코드 흐름 검사</h3>
    <p>이 이력에는 서버 코드 흐름 기록이 없습니다. 과거 분석을 추측하여 채우지 않습니다.</p></section>;
  const validated = snapshot.validatedFindings ?? [];
  const candidates = snapshot.findings.filter(candidate => !validated.some(f => f.evidence.some(e => JSON.stringify(e) === JSON.stringify(candidate))));
  if (compact) return <section className="analysis-coverage-brief" aria-label="서버 코드 흐름 요약"><h3>서버 코드 흐름 검사</h3>
    <p>{text(snapshot.status)} · {snapshot.validatedFindings == null ? '실행 경로 Finding 연결 미기록' : `정적 근거가 연결된 검토 항목 ${validated.length}건`} · 추가 문맥 확인 {candidates.length}건</p>
    <p>기존 배포 판단과 점수에 합산하지 않은 별도 결과입니다. ‘배포 전 직접 확인’에서 근거와 검사하지 못한 부분을 확인하세요.</p></section>;
  const current = Math.min(page, Math.max(0, Math.ceil(snapshot.files.length / 10) - 1));
  return <section className="server-analysis-section" aria-label="서버 코드 흐름 검사">
    <h3>서버 코드 흐름 검사</h3><p>{text(snapshot.status)}</p>
    <p className="review-caution">코드 구조에서 확인한 별도 검토 항목입니다. 기존 점수·위험 판정·반드시 처리 건수에 합산하지 않습니다. 항목이 없어도 전체 코드가 안전하다는 의미는 아닙니다.</p>
    {snapshot.findings.length === 0 && <p>지원 범위에서 요청 값이 쿼리 문자열로 전달되는 항목은 보고되지 않았습니다. 미검사·미지원 범위를 함께 확인하세요.</p>}
    <div className="vulnerability-list">{validated.map(finding => <article className="vulnerability-item action-finding" key={finding.findingId}>
      <span className="risk-badge risk-review_required">코드 흐름 · 추가 확인 필요</span>
      <h4>{finding.title}</h4>
      <p className="finding-location"><strong>확인할 파일</strong> {location(finding.location)}</p>
      <h4>어떤 입력인가요?</h4>
      <ul>{finding.evidence.map((e, i) => <li key={i}>{text(e.source.kind)} · <code className="finding-location">{location(e.source)}</code></li>)}</ul>
      <h4>왜 확인해야 하나요?</h4><p>{finding.riskExplanation}</p>
      <h4>어떻게 수정하나요?</h4><p>{finding.recommendedAction}</p>
      <h4>수정 후 확인</h4><ol>{finding.verificationSteps.map(step => <li key={step}>{step}</li>)}</ol>
      <details className="technical-details"><summary>Finding 기술 근거와 한계</summary>
        <p className="finding-location">{finding.findingId}</p><p>{finding.sourceType} · {finding.ruleId} · {finding.priority} · {finding.analyzerVersion}</p>
        <p>입력 전달과 실행 호출 구문을 확인한 것이며 실제 실행·공격 성공은 검증하지 않았습니다.</p>
        {finding.evidence.map((e, i) => <FlowEvidence key={i} finding={e} />)}
        <ul>{finding.executionLocations.map((entry, i) => <li key={i}>{text(entry.kind)} · <code className="finding-location">{location(entry)}</code></li>)}</ul>
        <p>비교 정책: {finding.comparisonPolicy}. 분석기 버전 변경이나 항목 미표시를 기존 문제의 해결로 계산하지 않습니다.</p>
      </details>
    </article>)}</div>
    {candidates.length > 0 && <h4>추가 문맥이 필요한 후보</h4>}
    <div className="vulnerability-list">{candidates.map((finding, i) => <article className="vulnerability-item action-finding" key={i}>
      <span className="risk-badge risk-review_required">코드 흐름 · 추가 확인 필요</span>
      <h4>요청 값이 데이터베이스 쿼리에 들어갑니다</h4><p>{finding.message}</p>
      <p>{snapshot.validatedFindings == null ? '이 이력은 실행 경로 Finding 연결 이전의 기록입니다. 과거 결과를 새 기준으로 추측하여 승격하지 않습니다.'
        : '중간 처리 또는 실행 호출을 충분히 확인하지 못해 검증된 흐름 Finding으로 연결하지 않았습니다.'}</p>
      <p>{finding.recommendation}</p>
      <details className="technical-details"><summary>기술 근거와 한계</summary>
        <FlowEvidence finding={finding} />
      </details>
    </article>)}</div>
    <details className="coverage-details"><summary>쿼리 값 처리와 방어 근거 ({snapshot.sqlUses.length})</summary>
      <ul className="coverage-file-list">{snapshot.sqlUses.map((sql, i) => <li key={i}>
        <code className="finding-location">{location(sql.location)}</code><span>{text(sql.kind)}</span>
        <span>{sql.defenses.map(d => text(d.kind)).join(' · ') || '확인한 바인딩 없음'}</span>
      </li>)}</ul><p>바인딩 확인은 인증·소유권 검증이나 모든 쿼리의 안전성을 보장하지 않습니다.</p>
    </details>
    <details className="coverage-details"><summary>인증·권한 관련 문맥 ({snapshot.authorizationContexts.length})</summary>
      {snapshot.authorizationContexts.map((context, i) => <div key={i}>
        <h4 className="finding-location">{location(context.entry)}</h4>
        <p>{context.checks.length ? `조건·로그인 문맥 ${context.checks.length}곳 확인` : '지원 범위에서 조건·로그인 문맥을 확인하지 못함'}</p>
        <ul>{[...context.checks, ...context.defenses].map((c, j) => <li key={j}>{text(c.kind)} · <code className="finding-location">{location(c)}</code></li>)}</ul>
        <p>권한 검증의 적절성은 확인되지 않았습니다. 검사가 보이지 않는다는 이유만으로 접근 권한 취약점으로 판단하지 않습니다.</p>
      </div>)}
    </details>
    <details className="coverage-details"><summary>파일별 구문 검사·추적 범위 ({snapshot.files.length})</summary>
      <ul className="coverage-file-list">{snapshot.files.slice(current * 10, current * 10 + 10).map((f, i) => <li key={i}>
        <code className="finding-location">{f.filePath}</code><span>{text(f.parseStatus)} · {text(f.flowStatus)} · 확인한 함수 {f.functionsAnalyzed}개</span>
        {f.prepareCallSites != null && <span>prepare 호출 구문 {f.prepareCallSites}곳 · 경로 확인 {f.tracedPrepareCallSites ?? '미기록'}곳 (모든 구문이 실제 SQL 호출이라는 뜻은 아님)</span>}
        {f.limitations.map(l => <span key={l}>{text(l)}</span>)}
      </li>)}</ul>
      {snapshot.files.length > 10 && <nav className="finding-pagination" aria-label="서버 분석 파일 페이지">
        <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)}>이전</button><span>{current + 1} / {Math.ceil(snapshot.files.length / 10)}</span>
        <button type="button" disabled={(current + 1) * 10 >= snapshot.files.length} onClick={() => setPage(current + 1)}>다음</button>
      </nav>}
      <p>분석기 {snapshot.analyzerVersion} · 파서 {snapshot.parserVersion ?? '미실행'}</p>
      <ul>{snapshot.limitations.map(l => <li key={l}>{text(l)}</li>)}</ul>
    </details>
  </section>;
}

function FlowEvidence({ finding }: { finding: ServerAnalysisSnapshot['findings'][number] }) {
  return <>
    <p className="finding-location">입력 위치: {location(finding.source)}</p><p className="finding-location">확인할 파일: {location(finding.sink)}</p>
    <ol>{finding.flow.map((step, index) => <li key={index}>{text(step.kind)} · <code className="finding-location">{location(step)}</code></li>)}</ol>
    <p>{finding.ruleId} · 흐름 근거 신뢰도 {finding.confidence} · {finding.disposition}</p>
    <p>확인한 처리: {finding.defenses.map(d => text(d.kind)).join(' · ') || '별도로 입증한 방어 처리 없음'}</p>
    <ul>{finding.limitations.map(item => <li key={item}>{text(item)}</li>)}</ul>
  </>;
}
