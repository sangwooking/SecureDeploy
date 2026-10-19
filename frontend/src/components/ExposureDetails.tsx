import type { ServerAnalysisSnapshot } from '../types/serverAnalysis';
const labels: Record<string,string> = {
  INTERNAL_ERROR_DETAIL:'내부 오류 스택 생성·참조', ERROR_DETAIL_CONTEXT_UNKNOWN:'예외·스택 문맥을 확인하지 못함',INTERNAL_DIAGNOSTIC_LOG_ONLY:'내부 진단 로그 전달 · HTTP 오류 응답으로 판단하지 않음',
  HTTP_RESPONSE_RETURN:'서버 진입점에서 반환한 응답',LOG_ARGUMENT:'로그에 전달한 인자',
  SENSITIVE_FLOW_CANDIDATE:'보호 정보 후보의 전달 경로 확인 · 실제 유출은 미검증',
  SENSITIVITY_UNVERIFIED:'정보가 실제로 민감한지 확인하지 못함',FLOW_UNRESOLVED:'값 변환·마스킹·실행 경로 일부 미확인',
  CREDENTIAL_SHAPED_LITERAL:'자격증명 형식의 코드 값 · 유효성 미확인',FRAMEWORK_SECRET_SETTING:'Django 서버 비밀 설정 참조 · 실제 값 미확인',
  AUTHENTICATION_HEADER:'요청의 인증·쿠키 헤더 · 서버 비밀값과 구분',ENVIRONMENT_VALUE_UNVERIFIED:'환경 설정 참조 · 민감성·실제 값 미확인',
  ASSIGNMENT:'변수로 전달', VARIABLE:'변수로 전달',FUNCTION_ARGUMENT:'함수 인자로 전달',
};
export function ExposureDetails({uses}:{uses:ServerAnalysisSnapshot['exposureUses']}) {
  if(uses==null)return <p>이 이력에는 정보 전달 근거가 기록되지 않았습니다. 과거 결과를 추측하지 않습니다.</p>;
  return <>
    <p>지원하는 서버 흐름의 출처와 응답·로그 전달을 구분했습니다. 실제 운영 노출·로그 접근 권한·브라우저 번들은 검사하지 않았습니다. 별도 검토 항목이며 기존 위험 건수·점수에는 합산하지 않습니다.</p>
    {uses.length===0&&<p>지원 범위에서 정보 전달 근거를 확인하지 못했습니다. 비밀정보 노출이 없다는 보증은 아닙니다.</p>}
    <ul className="coverage-file-list">{uses.map((use,i)=><li key={i}>
      <strong>{labels[use.kind]??'지원 범위 밖의 전달 지점'}</strong> <code>{use.location.filePath}:{use.location.line} · {use.location.functionName}</code>
      <p>{labels[use.status]??'확인 불가'}</p>
      <ul>{use.trace.map((source,j)=><li key={j}>{labels[source.kind]??'출처 문맥 미확인'} · <code>{source.filePath}:{source.line}</code></li>)}</ul>
      <details><summary>기술 정보와 한계</summary><p>{use.limitations.join(' · ')}</p></details>
    </li>)}</ul>
    <p>직접 확인: 응답·로그에 필요한 필드만 남기고 로컬 테스트에서 원문이 제외되는지 확인하세요. 공개 클라이언트 환경변수로 옮기는 것은 비밀 보호가 아닙니다. 실제 유출이 확인됐다면 자격증명 교체와 접근 기록 검토 후 재검사하세요.</p>
  </>;
}
