export class ApiRequestError extends Error {
 constructor(message:string,public readonly status:number,public readonly code?:string){super(message);this.name='ApiRequestError';}
}
export function requestProblem(error:unknown,subject='요청') {
 const status=error instanceof ApiRequestError?error.status:undefined;
 const messages:Record<number,string>={401:'로그인이 만료되었어요. 다시 로그인해 주세요.',403:'이 자료에 접근할 권한이 없어요.',404:`현재 서버에서 ${subject} 기능 또는 해당 자료를 찾을 수 없어요.`,405:`현재 서버는 ${subject} 요청을 지원하지 않아요.`,409:'원본·수정본 버전 또는 승인 상태가 달라졌어요. 최신 원본을 확인해 주세요.',422:'이 코드 구조나 저장된 분석 근거는 지원 범위에 맞지 않아요.',429:'요청 한도에 도달했어요. 잠시 후 다시 확인해 주세요.',501:`현재 서버는 ${subject} 기능을 지원하지 않아요.`,503:'서버 또는 AI Provider가 준비되지 않았어요. 수동 수정은 계속할 수 있어요.'};
 return {status,message:status?(messages[status]??'서버 요청을 완료하지 못했어요. 기존 결과는 보존됩니다.'):'서버에 연결하지 못했어요. 네트워크를 확인해 주세요.',retryable:status==null||status>=500&&![501,503].includes(status)};
}
