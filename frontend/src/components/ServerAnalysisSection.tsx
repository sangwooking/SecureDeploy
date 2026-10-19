import { useState } from 'react';
import type { AnalysisLocation, ServerAnalysisSnapshot } from '../types/serverAnalysis';
import { DeploymentAnalysisSection } from './DeploymentAnalysisSection';
import { AuthorizationContextDetails } from './AuthorizationContextDetails';
import { TokenSecurityDetails } from './TokenSecurityDetails';
import { ExposureDetails } from './ExposureDetails';
import { ServiceStabilityDetails } from './ServiceStabilityDetails';

const labels: Record<string, string> = {
  INTERNAL_ERROR_DETAIL:'내부 오류 스택 정보',ERROR_DETAIL_CONTEXT_UNKNOWN:'오류 스택 문맥 미확인',HTTP_CLIENT_CALL:'외부 HTTP 호출',
  HTTP_LIBRARY_VERSION_AND_PATCHES_UNVERIFIED:'HTTP 라이브러리·버전·변경 여부 미확인',PROXY_PLATFORM_AND_TOTAL_DEADLINE_UNKNOWN:'프록시·플랫폼 제한·전체 요청 기한 미확인',STATIC_CALL_NOT_SERVICE_FAILURE_PROOF:'정적 호출 근거이며 운영 장애를 확인한 것은 아님',
  CREDENTIAL_SHAPED_LITERAL:'자격증명 형식의 고정 값 · 원문은 저장하지 않음', FRAMEWORK_SECRET_SETTING:'Django 서버 비밀 설정 참조',
  AUTHENTICATION_HEADER:'인증·쿠키 헤더', ENVIRONMENT_VALUE_UNVERIFIED:'환경 설정 참조 · 실제 민감성 미확인', HTTP_RESPONSE:'응답 생성 위치',
  HTTP_RESPONSE_RETURN:'서버 응답 반환', LOG_ARGUMENT:'로그 인자 전달', STATIC_EXPOSURE_NOT_RUNTIME_LEAK_PROOF:'정적 전달 근거이며 실제 유출은 미검증',
  MASKING_LOG_ACCESS_AND_DEPLOYMENT_UNKNOWN:'외부 마스킹·로그 접근·배포 실행 문맥 미확인',
  TOKEN_API_CALL: 'JWT API 호출', TOKEN_SECURITY_USE: '토큰의 보안 사용 위치', TOKEN_CLAIM_DECISION: '토큰 값으로 접근 조건 판단',
  TOKEN_TRANSFORM_OR_EXTERNAL_VALIDATION_UNKNOWN: '다른 함수의 토큰 변환·검증 효과 미확인',
  TOKEN_VALUE_OR_EXECUTION_UNRESOLVED: '토큰 값 전달 또는 실행 경로 일부 미확인',
  TOKEN_CALLS_OUTSIDE_TRACED_FLOW: '구문에서 발견한 JWT API 후보 중 추적하지 못한 호출이 있음',
  PYJWT_2_API_SHAPE_LIBRARY_VERSION_NOT_VERIFIED: 'PyJWT 2.x API 형태 · 실제 설치 라이브러리·버전 미확인',
  EXTERNAL_TOKEN_VALIDATION_NOT_VERIFIED: '다른 계층의 토큰 검증 미확인',
  AUTH_LOGIC_CANDIDATE_NOT_EXPLOIT_PROOF: '비교·차단 로직의 검토 후보이며 실제 권한 우회 성공은 미검증',
  AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED: '외부 미들웨어·실행 환경의 추가 보호는 미확인',
  RESOURCE_LOOKUP: '요청 식별자로 리소스 조회', INVERTED_OWNER_REJECTION: '소유자 일치 시 차단하는 분기',
  RESOURCE_WRITE: '리소스 저장 호출', RESOURCE_DELETE: '리소스 삭제 호출',
  UPLOADED_FILE: '업로드된 파일 데이터', PATH_CONSTRUCTION: '파일 경로 구성', PATH_NORMALIZATION: '경로 정규화 · 디렉터리 제한 증거는 아님',
  FILE_ACCESS_CALL: '파일 접근 호출', DESERIALIZATION_CALL: '데이터 복원 호출',
  INPUT_IN_FILE_PATH: '요청 값이 파일 경로에 전달됨', INPUT_TO_UNSAFE_DESERIALIZATION: '요청 데이터가 위험한 복원 호출에 전달됨',
  LEXICALLY_CONFINED_PATH: '고정 기준 디렉터리와 safe_join의 문자열 경계 제한 확인',
  SAFE_PARSER_DECLARATION: 'JSON 또는 안전 로더 호출 형태 확인 · 다른 위험까지 보증하지 않음',
  FIXED_SOURCE_NO_REQUEST_FLOW: '고정 값에서 호출 · 요청 입력 전달은 확인되지 않음', UNRESOLVED_RESOURCE: '파일·데이터 출처 또는 처리 과정 미확인',
  RESOURCE_FLOW_UNRESOLVED: '입력 전달·변환·실행 조건 중 일부를 확인하지 못함',
  RESOURCE_CALLS_OUTSIDE_TRACED_FLOW: '구문에서 발견한 파일·복원 API 후보 중 추적하지 못한 호출이 있음',
  DJANGO_SAFE_JOIN_LITERAL_BASE: '고정 기준 디렉터리의 Django safe_join 확인',
  SYMLINKS_PERMISSIONS_AND_RUNTIME_NOT_VERIFIED: '심볼릭 링크·파일시스템 상태·접근 권한·운영 실행은 미검증',
  LIBRARY_VERSION_AND_EXPLOITABILITY_NOT_VERIFIED: '라이브러리 버전별 동작과 실제 공격 가능성은 미검증',
  BOUNDED_PYTHON_FILE_AND_DESERIALIZATION_ONLY: 'Python의 지원 파일 API·pickle·YAML 호출만 제한적으로 추적',
  MODULE_OBJECT_WRITE_UNRESOLVED: '모듈 객체 변경으로 호출 대상의 원래 동작을 확인하지 못함',
  LAZY_DESERIALIZATION_EXECUTION_NOT_VERIFIED: '지연 복원 결과의 실제 순회·실행 여부는 확인하지 못함',
  UNSUPPORTED_ARGUMENT_TYPE: '요청 문자열은 이 복원 API가 요구하는 바이트 형식과 다름 · 취약점으로 연결하지 않음',
  PICKLE_LOADS_REQUIRES_BYTES_NOT_REQUEST_TEXT: 'pickle.loads는 바이트 입력을 요구합니다. 확인한 문자열 흐름을 실행 가능한 복원 위험으로 계산하지 않았습니다.',
  COMPLETE: '제한된 범위 확인 완료', PARTIAL: '일부만 확인', NOT_APPLICABLE: '대상 파일 없음',
  UNAVAILABLE: '분석하지 못함', TIMEOUT: '분석 시간 초과', DISABLED: '실행하지 않음',
  PARSED: '구문 확인', PARSE_FAILED: '구문 파싱 실패', LIMIT_EXCEEDED: '크기·자원 제한', NOT_RUN: '미실행',
  SUPPORTED_FLOW_ANALYZED: '지원하는 값 전달 경로 확인', NOT_SUPPORTED: '지원되는 서버 흐름 아님',
  INPUT_IN_QUERY: '요청 값이 쿼리 문자열에 포함', PARAMETERIZED_QUERY: '정적 쿼리와 값 바인딩 확인',
  STATIC_QUERY: '정적인 쿼리 구성 확인', UNRESOLVED_QUERY: '쿼리 구성 확인 불가',
  QUERY_PARAMETER: 'URL에서 받은 값', REQUEST_BODY: '요청 본문', ROUTE_PARAMETER: '경로에서 받은 값',
  REQUEST_URL: '요청 URL', VARIABLE: '변수로 전달', ASSIGNMENT: '변수에 대입', FUNCTION_ARGUMENT: '함수 인자로 전달',
  D1_PREPARE: '데이터베이스 쿼리 구성', VALUE_BINDING: '값 매개변수 바인딩',
  SQL_STRING_CONSTRUCTION: '문자열 구성 · 실제 사용 위치는 전달 근거 참조', SQL_EXECUTION_CALL: '쿼리 실행 호출',
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
  REQUEST_HEADER: '요청 헤더에서 받은 값', HTTP_REQUEST_CALL: '서버 HTTP 요청 호출', URL_STRING_CONSTRUCTION: '요청 주소 문자열 구성',
  INPUT_IN_DESTINATION: '외부 입력이 요청 목적지를 결정할 수 있음', FIXED_DESTINATION: '초기 목적지는 고정됨',
  ALLOWLISTED_DESTINATION: '파싱한 프로토콜·호스트의 정확한 허용 목록 확인', UNRESOLVED_DESTINATION: '목적지 결정 과정 확인 불가',
  PARSED_URL_ALLOWLIST: '파싱한 URL 속성의 정확한 허용 목록',
  DESTINATION_FLOW_UNRESOLVED: 'URL 변환·방어·실행 경로 일부 미확인', URL_MUTATION_UNRESOLVED: 'URL 속성 변경을 완전히 추적하지 못함',
  REDIRECT_DNS_REACHABILITY_NOT_VERIFIED: '리다이렉트·DNS 재해석·실제 네트워크 접근 가능성 미검증',
  PORT_POLICY_NOT_VERIFIED: '허용 목록의 포트 정책은 별도 확인 필요',
  URL_PROPERTY_WRITE: 'URL 속성 대입 확인·함수 간 변경은 제한적으로 추적', URL_QUERY_WRITE: '검색값 변경 확인·함수 간 변경은 제한적으로 추적',
  HEADER_MUTATION_PARTIAL: '요청 헤더 변경 후의 값을 완전히 추적하지 못함',
  HTTP_CALLS_OUTSIDE_TRACED_FLOW: 'fetch 구문 중 확인한 서버 경로에 연결되지 않은 부분이 있음',
  WHOLE_URL: '전체 주소', HOST_OR_AUTHORITY: '호스트 또는 주소 권한부', WHOLE_URL_OR_HOST: '전체 주소 또는 호스트',
  PATH_QUERY_OR_NONE: '경로·검색값 또는 입력 영향 없음', UNKNOWN: '확인 불가',
  SERVER_ENTRY: '서버 요청 진입점', AUTH_DECLARATION: '인증·권한 설정 선언',
  BOUNDED_DJANGO_DRF_ONLY: 'Django/DRF의 일부 진입점과 지원되는 값 전달만 검사',
  MIDDLEWARE_SETTINGS_AND_OWNERSHIP_NOT_VERIFIED: '미들웨어·전역 설정·리소스 소유권은 미검증',
  STATIC_FLOW_NOT_EXPLOIT_PROOF: '정적 전달 경로이며 공격 성공을 확인한 것은 아님',
  NO_OS_SANDBOX: '시간·입출력 제한 프로세스이며 OS 수준 완전 격리는 아님',
  RSS_CHECK_NOT_HARD_MEMORY_LIMIT: '이 환경은 메모리 사용량 점검이며 OS 강제 메모리 제한은 아님',
  SQL_CALLS_OUTSIDE_TRACED_FLOW: '확인한 서버 경로 밖에도 SQL 호출 후보 구문이 있음',
  LAZY_RAW_EXECUTION_NOT_VERIFIED: 'raw 쿼리의 지연 실행 시점 미확인',
  ROUTE_TARGET_UNRESOLVED: 'URL 경로의 요청 처리 함수를 확인하지 못함',
  AST_NODE_LIMIT: '구문 트리 크기 제한', RESULT_LIMIT_EXCEEDED: '기록 가능한 근거 수 제한',
  ASYNC_EXECUTION_UNRESOLVED: '비동기 호출 실행 흐름 미확인',
  MUTABLE_OBJECT_WRITE_UNRESOLVED: '객체 변경과 별칭의 영향을 확인하지 못함',
  CONTEXT_MANAGER_UNRESOLVED: '컨텍스트 관리자의 실행 흐름 미확인',
  ORM_VALUE_QUERY: 'ORM 값 매개변수 호출 형태 확인', ORM_VALUE_PARAMETERS: 'ORM의 값 매개변수 사용',
  NUMERIC_ROUTE_CONVERTER: '정수형 경로 변환 선언', ROUTE_PARAMETERS_UNRESOLVED: '경로 인자의 전달 방식 미확인',
  DECORATOR_EXECUTION_UNRESOLVED: '사용자 정의 데코레이터의 실행 영향 미확인',
  CUSTOM_MANAGER_AND_RUNTIME_NOT_VERIFIED: '사용자 정의 Manager와 실제 실행 환경은 미검증',
  INPUT_GUARD_UNRESOLVED: '입력에 대한 사용자 정의 검증 함수의 효과 미확인',
  FILE_COUNT_LIMIT: '분석할 파일 수 상한으로 선택하지 못함',
  FILE_CHARACTER_LIMIT: '이 파일의 문자 수 상한 초과',
  TOTAL_CHARACTER_LIMIT: '전체 소스 문자 수 상한으로 선택하지 못함',
  DJANGO_ROUTING_HINT: 'Django 경로 설정 후보를 우선 선택',
  DJANGO_ENTRY_HINT: 'Django/DRF 요청 처리 선언 후보를 우선 선택',
  DJANGO_SETTINGS_REFERENCE_HINT: 'Django 설정 모듈 참조 후보를 우선 선택',
  RELATED_IMPORT_HINT: '요청 경로 후보와 연결된 정적 import 참조',
  DETERMINISTIC_FALLBACK: '연결 근거 밖의 나머지 파일을 경로순 선택',
  SELECTION_HINT_LIMIT: '파일 선택용 사전 조사 상한으로 연결 관계를 일부 확인하지 못함',
  LEXICAL_SELECTION_HINTS_NOT_VERIFIED_ENTRIES: '파일 선택 단서는 우선순위용이며 실제 진입점은 구문 분석으로 별도 확인',
  SOURCE_LIMITS_OR_SENSITIVE_PATHS_OMITTED: '소스 제한 또는 민감한 경로로 선택하지 못한 파일이 있음',
  OMITTED_FILE_DETAILS_TRUNCATED: '미선택 파일 기록 일부를 생략함. 표시 파일 수는 전체 파일 수가 아님',
  CALL_ARGUMENT_BINDING_UNRESOLVED: '함수 인자를 올바르게 전달할 수 있는지 확인하지 못함',
  UNPACKING_UNRESOLVED: '묶음 값의 개별 변수 전달을 확인하지 못함',
};
const text = (value: string) => labels[value] ?? (/^[A-Z_]+$/.test(value) ? '지원 범위 밖이거나 추가 확인이 필요한 처리' : value);
const location = (value: AnalysisLocation) => `${value.filePath}:${value.line} · ${value.functionName}`;

export function ServerAnalysisSection({ snapshot, compact = false }: { snapshot?: ServerAnalysisSnapshot | null; compact?: boolean }) {
  return <>
    <DeploymentAnalysisSection snapshot={snapshot?.deploymentAnalysis} compact={compact} />
    <LanguageAnalysisSection snapshot={snapshot} compact={compact} />
    {snapshot?.pythonAnalysis && snapshot.pythonAnalysis.status !== 'NOT_APPLICABLE' &&
      <LanguageAnalysisSection snapshot={snapshot.pythonAnalysis} compact={compact} python />}
  </>;
}

function LanguageAnalysisSection({ snapshot, compact = false, python = false }: { snapshot?: ServerAnalysisSnapshot | null; compact?: boolean; python?: boolean }) {
  const [page, setPage] = useState(0);
  if (!snapshot) return compact ? null : <section className="analysis-coverage-brief"><h3>서버 코드 흐름 검사</h3>
    <p>이 이력에는 서버 코드 흐름 기록이 없습니다. 과거 분석을 추측하여 채우지 않습니다.</p></section>;
  const validated = snapshot.validatedFindings ?? [];
  const candidates = snapshot.findings.filter(candidate => !validated.some(f => f.evidence.some(e => JSON.stringify(e) === JSON.stringify(candidate))));
  const title = python ? 'Python 서버 코드 흐름 검사' : '서버 코드 흐름 검사';
  if (compact) return <section className="analysis-coverage-brief" aria-label={python ? 'Python 서버 코드 흐름 요약' : '서버 코드 흐름 요약'}><h3>{title}</h3>
    <p>{text(snapshot.status)} · {snapshot.validatedFindings == null ? '실행 경로 Finding 연결 미기록' : `정적 근거가 연결된 검토 항목 ${validated.length}건`} · 추가 문맥 확인 {candidates.length}건</p>
    {python && <PythonCoverageSummary snapshot={snapshot} />}
    <p>기존 배포 판단과 점수에 합산하지 않은 별도 결과입니다. ‘배포 전 직접 확인’에서 근거와 검사하지 못한 부분을 확인하세요.</p></section>;
  const current = Math.min(page, Math.max(0, Math.ceil(snapshot.files.length / 10) - 1));
  return <section className="server-analysis-section" aria-label={title}>
    <h3>{title}</h3><p>{text(snapshot.status)}</p>
    {python && <p>Django/DRF에서 연결된 일부 요청 경로의 SQL·파일 경로·pickle/YAML 값 전달을 확인한 결과입니다. 전체 Python 코드·인증·권한·미들웨어를 검사한 것은 아닙니다.</p>}
    {python && <PythonCoverageSummary snapshot={snapshot} />}
    <p className="review-caution">코드 구조에서 확인한 별도 검토 항목입니다. 기존 점수·위험 판정·반드시 처리 건수에 합산하지 않습니다. 항목이 없어도 전체 코드가 안전하다는 의미는 아닙니다.</p>
    {snapshot.findings.length === 0 && <p>지원 범위에서 보고된 요청 값 전달 위험 항목은 없습니다. 미검사·미지원 범위를 함께 확인하세요.</p>}
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
      <h4>{finding.ruleId === 'TS_SSRF_INPUT_FLOW' ? '서버 요청 주소의 처리 과정을 확인해 주세요'
        : finding.ruleId === 'PY_FILE_PATH_INPUT_FLOW' ? '입력된 파일 경로의 제한을 확인해 주세요'
        : finding.ruleId === 'PY_UNSAFE_DESERIALIZATION_INPUT_FLOW' ? '외부 데이터의 복원 방식을 확인해 주세요'
        : finding.ruleId === 'PY_AUTHORIZATION_INVERTED_OWNER_GUARD' ? '사용자 비교와 차단 분기의 의도를 확인해 주세요'
        : finding.ruleId === 'PY_JWT_UNVERIFIED_ACCESS_DECISION' ? '토큰을 신뢰하기 전 서명 검증을 확인해 주세요'
        : finding.ruleId === 'PY_JWT_FIXED_SIGNING_KEY' ? '토큰 서명 키의 관리 방식을 확인해 주세요'
        : finding.ruleId.endsWith('_SENSITIVE_DATA_EXPOSURE') ? '보호할 정보가 응답·로그에 전달되는지 확인해 주세요'
        : finding.ruleId.endsWith('_ERROR_DETAIL_EXPOSURE') ? '내부 오류 정보가 응답에 포함되는지 확인해 주세요'
        : finding.ruleId==='PY_HTTP_TIMEOUT_REVIEW' ? '외부 요청의 대기 제한을 확인해 주세요' : '요청 값이 데이터베이스 쿼리에 들어갑니다'}</h4><p>{finding.message}</p>
      <p>{snapshot.validatedFindings == null ? '이 이력은 실행 경로 Finding 연결 이전의 기록입니다. 과거 결과를 새 기준으로 추측하여 승격하지 않습니다.'
        : '중간 처리 또는 실행 호출을 충분히 확인하지 못해 검증된 흐름 Finding으로 연결하지 않았습니다.'}</p>
      <p>{finding.recommendation}</p>
      <details className="technical-details"><summary>기술 근거와 한계</summary>
        <FlowEvidence finding={finding} />
      </details>
    </article>)}</div>
    <details className="coverage-details"><summary>응답·로그 정보 전달 근거 ({snapshot.exposureUses?.length ?? '미기록'})</summary><ExposureDetails uses={snapshot.exposureUses}/></details>
    {python&&<details className="coverage-details"><summary>외부 요청 대기 제한 근거 ({snapshot.serviceUses?.length??'미기록'})</summary><ServiceStabilityDetails uses={snapshot.serviceUses}/></details>}
    {python && <details className="coverage-details"><summary>토큰 서명·사용 근거 ({snapshot.tokenUses?.length ?? '미기록'})</summary>
      <TokenSecurityDetails uses={snapshot.tokenUses} />
    </details>}
    {python && <details className="coverage-details"><summary>파일 접근·데이터 복원 근거 ({snapshot.resourceUses?.length ?? '미기록'})</summary>
      {snapshot.resourceUses == null ? <p>이 이력에는 파일 접근·데이터 복원 추적 기록이 없습니다. 과거 결과를 새 기준으로 판단하지 않습니다.</p>
        : <ul className="coverage-file-list">{snapshot.resourceUses.map((use, i) => <li key={i}>
          <code className="finding-location">{location(use.location)}</code><span>{text(use.kind)}</span>
          {use.defenses.map((d, j) => <span key={`d${j}`}>{text(d.kind)}</span>)}
          {use.limitations.map(l => <span key={l}>{text(l)}</span>)}
        </li>)}</ul>}
      <p>문자열 경계 검사를 확인했더라도 심볼릭 링크·운영 파일 권한을 보증하지 않습니다. 고정 데이터도 신뢰된 운영 데이터라고 확정하지 않습니다. Java·일반 Node.js 파일 흐름은 이번 범위에 포함되지 않습니다.</p>
    </details>}
    <details className="coverage-details"><summary>쿼리 값 처리와 방어 근거 ({snapshot.sqlUses.length})</summary>
      <ul className="coverage-file-list">{snapshot.sqlUses.map((sql, i) => <li key={i}>
        <code className="finding-location">{location(sql.location)}</code><span>{text(sql.kind)}</span>
        <span>{sql.defenses.map(d => text(d.kind)).join(' · ') || '확인한 바인딩 없음'}</span>
      </li>)}</ul><p>바인딩 확인은 인증·소유권 검증이나 모든 쿼리의 안전성을 보장하지 않습니다.</p>
    </details>
    {!python && <details className="coverage-details"><summary>서버 HTTP 요청 목적지 ({snapshot.httpUses?.length ?? '미기록'})</summary>
      {snapshot.httpUses == null ? <p>이 이력에는 HTTP 목적지 추적 기록이 없습니다. 과거 결과를 새 기준으로 판단하지 않습니다.</p>
        : <ul className="coverage-file-list">{snapshot.httpUses.map((http, i) => <li key={i}>
          <code className="finding-location">{location(http.location)}</code><span>{text(http.kind)}</span>
          <span>입력이 영향을 주는 영역: {text(http.controlledPart)}</span>
          {http.defenses.map((d, j) => <span key={`d${j}`}>{text(d.kind)}</span>)}
          {http.limitations.map(l => <span key={l}>{text(l)}</span>)}
        </li>)}</ul>}
      <p>고정된 주소나 허용 목록을 확인했더라도 리다이렉트·DNS 재해석·내부망 접근까지 안전하다고 보증하지 않습니다. SSRF는 서버가 의도하지 않은 주소로 요청하게 되는 위험입니다.</p>
    </details>}
    <details className="coverage-details"><summary>인증·권한 관련 문맥 ({snapshot.authorizationContexts.length})</summary>
      {snapshot.authorizationContexts.map((context, i) => <div key={i}>
        <h4 className="finding-location">{location(context.entry)}</h4>
        {context.details && <AuthorizationContextDetails details={context.details} />}
        <p>{context.checks.length ? `조건·로그인 문맥 ${context.checks.length}곳 확인` : '지원 범위에서 조건·로그인 문맥을 확인하지 못함'}</p>
        <ul>{[...context.checks, ...context.defenses].map((c, j) => <li key={j}>{text(c.kind)} · <code className="finding-location">{location(c)}</code></li>)}</ul>
        <p>권한 검증의 적절성은 확인되지 않았습니다. 검사가 보이지 않는다는 이유만으로 접근 권한 취약점으로 판단하지 않습니다.</p>
      </div>)}
    </details>
    <details className="coverage-details"><summary>파일별 구문 검사·추적 범위 ({snapshot.files.length})</summary>
      <ul className="coverage-file-list">{snapshot.files.slice(current * 10, current * 10 + 10).map((f, i) => <li key={i}>
        <code className="finding-location">{f.filePath}</code><span>{text(f.parseStatus)} · {text(f.flowStatus)} · 확인한 함수 {f.functionsAnalyzed}개</span>
        {python && <span>확인한 요청 진입점 {f.entrypoints}개{f.selectionReason ? ` · ${text(f.selectionReason)}` : ''}</span>}
        {f.prepareCallSites != null && <span>{python ? 'SQL 실행 후보' : 'prepare'} 호출 구문 {f.prepareCallSites}곳 · 경로 확인 {f.tracedPrepareCallSites ?? '미기록'}곳 (모든 구문이 실제 SQL 호출이라는 뜻은 아님)</span>}
        {f.httpCallSites != null && <span>fetch 호출 구문 {f.httpCallSites}곳 · 목적지 추적 {f.tracedHttpCallSites ?? '미기록'}곳 (모든 HTTP client를 지원하는 것은 아님)</span>}
        {python && f.resourceCallSites != null && <span>파일·복원 API 후보 구문 {f.resourceCallSites}곳 · 호출 근거 추적 {f.tracedResourceCallSites ?? '미기록'}곳 (이름 후보이며 실제 API 사용을 모두 증명한 것은 아님)</span>}
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

function PythonCoverageSummary({ snapshot }: { snapshot: ServerAnalysisSnapshot }) {
  const parsed = snapshot.files.filter(f => f.parseStatus === 'PARSED').length;
  const traced = snapshot.files.filter(f => f.functionsAnalyzed > 0).length;
  const limited = snapshot.files.filter(f => f.parseStatus === 'LIMIT_EXCEEDED').length;
  const failed = snapshot.files.filter(f => f.parseStatus === 'PARSE_FAILED').length;
  const entries = snapshot.files.reduce((sum, f) => sum + f.entrypoints, 0);
  return <div aria-label="Python 검사 범위 단계">
    {snapshot.authorizationContexts.some(c => c.details != null) && <p>권한 상세 문맥 {snapshot.authorizationContexts.filter(c => c.details != null).length}개 · 로그인 선언과 객체 접근 권한은 별도로 확인했습니다. 실제 활성 정책과 외부 보호는 미확인입니다.</p>}
    {snapshot.selectionCoverage && <p>공통 파일 수집기를 통과한 Python 파일 {snapshot.selectionCoverage.discoveredFiles}개 · 분석기에 전달 {snapshot.selectionCoverage.submittedFiles}개 · 미선택 {snapshot.selectionCoverage.omittedFiles}개</p>}
    <p>파일 기록 {snapshot.files.length}개 · 구문 파싱 {parsed}개 · 요청 진입점 {entries}개 · 값 전달을 추적한 파일 {traced}개</p>
    <p>자원 제한 {limited}개 · 파싱 실패 {failed}개 · 파싱 후 흐름 미추적 {snapshot.files.filter(f => f.parseStatus === 'PARSED' && f.functionsAnalyzed === 0).length}개</p>
    <p>파싱은 코드 구조를 읽었다는 뜻이며 보안 검사를 모두 마쳤다는 뜻이 아닙니다. 값 전달을 추적한 파일도 일부 함수·경로만 확인했습니다.</p>
    {(snapshot.limitations.includes('OMITTED_FILE_DETAILS_TRUNCATED') || (snapshot.selectionCoverage?.omittedDetails ?? 0) > 0) && <p>{text('OMITTED_FILE_DETAILS_TRUNCATED')}</p>}
  </div>;
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
