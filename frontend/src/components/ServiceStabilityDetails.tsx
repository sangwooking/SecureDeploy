import type {ServerAnalysisSnapshot} from '../types/serverAnalysis';
const labels:Record<string,string>={
 REQUESTS_DEFAULT_WITHOUT_TIMEOUT:'Requests 직접 호출에 타임아웃 지정 없음',EXPLICIT_TIMEOUT_DISABLED:'타임아웃을 명시적으로 해제한 호출',
 HTTPX_DEFAULT_INACTIVITY_TIMEOUT:'HTTPX 기본 네트워크 비활동 제한 적용 형태 · 전체 요청 기한 아님',
 POSITIVE_TIMEOUT_NOT_TOTAL_DEADLINE:'양수 타임아웃 지정 · 전체 요청 기한 보증 아님',TIMEOUT_SETTING_UNRESOLVED:'동적·미지원 타임아웃 설정',HTTP_CALL_PATH_UNRESOLVED:'외부 호출 실행 경로 일부 미확인',
};
export function ServiceStabilityDetails({uses}:{uses:ServerAnalysisSnapshot['serviceUses']}){
 if(uses==null)return <p>이 이력에는 외부 요청 대기 제한 근거가 없습니다. 과거 결과를 추측하지 않습니다.</p>;
 return <><p>지원 Django/DRF 진입점의 직접 Requests·HTTPX API 형태만 확인했습니다. 실제 설치 버전·프록시·플랫폼·전체 요청 기한과 운영 장애는 미확인입니다. 별도 검토 결과이며 기존 위험 건수·점수에 합산하지 않습니다.</p>
 {uses.length===0&&<p>지원 호출 근거가 없습니다. 자원 보호가 충분하다는 의미는 아닙니다.</p>}
 <ul className="coverage-file-list">{uses.map((use,i)=><li key={i}><strong>{labels[use.status]??'설정·실행 범위 확인 불가'}</strong><p><code>{use.location.filePath}:{use.location.line} · {use.location.functionName}</code> · {use.kind}</p>
 <details><summary>기술 근거와 한계</summary><p>{use.limitations.join(' · ')}</p>{use.trace.map((l,j)=><p key={j}><code>{l.filePath}:{l.line}</code></p>)}</details></li>)}</ul>
 <p>직접 확인: 연결·읽기 타임아웃과 전체 요청 기한을 구분하고 지연 Mock으로 로컬 취소·오류·자원 반환을 테스트한 뒤 재검사하세요. 실제 외부 서비스에 부하를 보내지 마세요.</p></>;
}
