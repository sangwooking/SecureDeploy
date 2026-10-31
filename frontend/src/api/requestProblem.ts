export class ApiRequestError extends Error {
 constructor(message:string,public readonly status:number,public readonly code?:string){super(message);this.name='ApiRequestError';}
}
export function requestProblem(error:unknown,subject='요청') {
 const status=error instanceof ApiRequestError?error.status:undefined;
 const messages:Record<number,string>={401:'로그인이 만료되었어요. 다시 로그인해 주세요.',403:'이 자료에 접근할 권한이 없어요.',404:`현재 서버에서 ${subject} 기능 또는 해당 자료를 찾을 수 없어요.`,405:`현재 서버는 ${subject} 요청을 지원하지 않아요.`,409:'원본·수정본 버전 또는 승인 상태가 달라졌어요. 최신 원본을 확인해 주세요.',422:'이 코드 구조나 저장된 분석 근거는 지원 범위에 맞지 않아요.',429:'요청 한도에 도달했어요. 잠시 후 다시 확인해 주세요.',501:`현재 서버는 ${subject} 기능을 지원하지 않아요.`,503:'서버 또는 AI Provider가 준비되지 않았어요. 수동 수정은 계속할 수 있어요.'};
 if(subject==='업데이트 계획'&&status){const why:Record<number,string>={400:'업데이트 요청 형식을 확인해야 해요.',401:'로그인이 만료됐어요.',403:'이 검사에 접근할 권한이 없어요.',404:'이 서버에 업데이트 계획 API가 없거나 해당 검사에 접근할 수 없어요.',405:'현재 Backend 버전은 업데이트 계획 요청을 지원하지 않아요.',409:'저장된 근거·Revision·해시가 변경됐어요. 원본 검사를 다시 선택해 주세요.',422:'저장된 SCA 근거나 패키지 관리자 구조가 업데이트 지원 범위와 맞지 않아요.',429:'요청 한도에 도달했어요.',500:'업데이트 계획 처리 중 서버가 실패했어요. 해당 요청의 서버 로그 확인이 필요해요.',502:'업데이트 서버 연결을 완료하지 못했어요.',503:'현재 업데이트 계획 서비스가 준비되지 않았어요.'};return {status,message:`${why[status]??'업데이트 계획 요청을 완료하지 못했어요.'} (HTTP ${status}) 기존 분석 결과는 보존됩니다.`,retryable:status>=500&&status!==503};}
 if(subject==='공식 공지 보완 조회') {
  const why:Record<number,string>={401:'로그인이 만료됐어요.',403:'이 검사의 공지 근거에 접근할 권한이 없어요.',404:'해당 검사 또는 공식 공지 보완 조회 API를 찾을 수 없어요.',405:'현재 서버는 공식 공지 보완 조회를 지원하지 않아요.',422:'저장된 공지 근거가 보완 조회 지원 범위와 맞지 않아요.',429:'공식 공지 조회 한도에 도달했어요.',500:'공식 공지 보완 조회 처리 중 서버가 실패했어요.',502:'공식 공지 조회 서버 연결을 완료하지 못했어요.',503:'공식 공지 보완 조회 서비스가 준비되지 않았어요.'};
  return {status,message:`${status?(why[status]??'공식 공지 보완 조회를 완료하지 못했어요.')+' (HTTP '+status+')':'공식 공지 조회 서버에 연결하지 못했어요. 네트워크를 확인해 주세요.'} 기존 저장된 분석 근거는 유지됩니다.`,retryable:status==null||status>=500};
 }
 const specific:Record<string,string>={SOURCE_MISMATCH:'검사 당시 코드·ZIP과 현재 원본이 달라 바로 수정할 수 없어요. 검사 당시 원본을 선택하거나 새 버전으로 다시 검사해 주세요.',SOURCE_UNAVAILABLE:'기록된 원본을 확보하지 못했어요. 읽기 권한·Commit 보존 여부와 연결을 확인해 주세요. 최신 코드로 대체하지 않았습니다.',AUTH_STORE_UNAVAILABLE:'인증 저장소 연결이 일시적으로 중단됐어요. 미저장 편집을 내보내고 연결 복구 후 저장 상태를 확인해 주세요.',WORKSPACE_ALREADY_OPEN:'진행 중인 수정 작업이 있어요. 기존 작업을 확인해 이어서 진행해 주세요.',WORKSPACE_REVISION_CONFLICT:'다른 탭의 저장과 충돌했어요. 현재 편집을 내보낸 뒤 최신 저장본을 확인해 주세요.'};
 if(error instanceof ApiRequestError&&error.code&&specific[error.code])return {status,message:specific[error.code],retryable:false};
 return {status,message:status?(messages[status]??'서버 요청을 완료하지 못했어요. 기존 결과는 보존됩니다.'):'서버에 연결하지 못했어요. 네트워크를 확인해 주세요.',retryable:status==null||status>=500&&![501,503].includes(status)};
}
