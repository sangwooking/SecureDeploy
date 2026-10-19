import type { ServerAnalysisSnapshot } from '../types/serverAnalysis';

const labels: Record<string, string> = {
  SIGN: '토큰 서명 생성', DECODE: '토큰 내용 읽기',
  EXPLICITLY_DISABLED: '서명 검증 생략 옵션 확인', DEFAULT_OR_ENABLED_CALL: '기본 또는 검증 활성화 호출 형태 · 검증 성공 보증 아님',
  VERIFICATION_OPTIONS_UNRESOLVED: '서명 검증 옵션 확인 불가', LEGACY_VERIFY_ARGUMENT_VERSION_DEPENDENT: '구형 verify 인자 · 설치 버전에 따른 동작 확인 필요',
  HMAC_SIGN_CALL: 'HMAC 서명 호출 형태 · 알고리즘 자체는 취약점 아님', SIGNING_OPTIONS_UNRESOLVED: '서명 방식 확인 불가',
  FIXED_LITERAL: '코드에 고정된 키 사용 · 값은 저장하지 않음', FIXED_EXAMPLE: '예시 값 형태 · 실제 사용 여부 확인 필요',
  ENVIRONMENT_REFERENCE: '환경 설정 참조 · 키 품질·실제 값은 미확인', ENVIRONMENT_WITH_LITERAL_FALLBACK: '환경 설정에 고정 기본값 존재', UNKNOWN: '키 출처 확인 불가',
  ACCESS_REJECTION_BRANCH: '읽은 값이 접근 거부 조건에 사용됨', CONDITIONAL_USE_NOT_PROVEN_AUTHORIZATION: '조건 분기에 사용 · 인증·권한 판단인지는 미확인',
  NO_SECURITY_DECISION_TRACED: '보안 판단에 사용하는 경로는 확인하지 못함',
};

export function TokenSecurityDetails({ uses }: { uses: ServerAnalysisSnapshot['tokenUses'] }) {
  if (uses == null) return <p>이 이력에는 토큰 처리 근거가 기록되지 않았습니다. 과거 결과를 추측하지 않습니다.</p>;
  return <>
    <p>지원 Django/DRF 흐름의 PyJWT 2.x API 형태만 검사했습니다. 실제 설치 라이브러리·버전, 외부 검증, 전체 암호화 안전성은 확인하지 않았습니다. 단순 디코딩은 인증 검증과 다릅니다.</p>
    {uses.length === 0 && <p>추적한 토큰 호출이 없습니다. 토큰 처리 전체가 안전하다는 의미는 아닙니다.</p>}
    <ul className="coverage-file-list">{uses.map((use, i) => <li key={i}>
      <strong>{labels[use.operation] ?? '지원 범위 밖의 토큰 호출'}</strong> <code>{use.location.filePath}:{use.location.line} · {use.location.functionName}</code>
      <p>{labels[use.signatureStatus] ?? '검증 상태 확인 불가'}</p>
      <p>{labels[use.keySource] ?? '키 출처 확인 불가'}</p>
      <p>{labels[use.usageStatus] ?? '사용 문맥 확인 불가'}</p>
      {use.trace.length > 0 && <p>입력·사용 위치: {use.trace.map(l => `${l.filePath}:${l.line}`).join(' → ')}</p>}
      <details><summary>기술 정보와 한계</summary><p>{use.limitations.join(' · ')}</p></details>
    </li>)}</ul>
    <p>직접 확인: 실제 JWT 라이브러리·버전과 다른 계층의 서명 검증을 확인하세요. 로컬 테스트에서 변조·만료 토큰과 잘못된 키를 거부하는지 확인하고 수정 후 재검사하세요. 키·토큰 원문을 화면이나 로그에 출력하지 마세요.</p>
  </>;
}
