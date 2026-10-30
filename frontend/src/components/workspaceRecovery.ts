import { ApiRequestError } from '../api/requestProblem';
import type { EditingWorkspace } from '../api/editingApi';

// Missing, expired and foreign workspaces intentionally share HTTP 404.
export function workspaceRecoveryProblem(error: unknown) {
  const status=error instanceof ApiRequestError?error.status:undefined;
  const message=status===401?'다시 로그인한 뒤 이전 작업을 확인해 주세요.'
    :status===403?'현재 계정으로 이 작업에 접근할 수 없어요.'
    :status===404?'이전 수정 작업을 이어갈 수 없어요. 작업이 없거나 접근할 수 없습니다.'
    :error instanceof Error&&error.message==='WORKSPACE_REVIEW_MISMATCH'?'이 검사와 다른 작업 공간이 연결되어 있어요.'
    :status?'서버에서 이전 작업을 확인하지 못했어요. 잠시 후 다시 시도해 주세요.'
    :'서버에 연결하지 못했어요. 연결을 확인한 뒤 다시 시도해 주세요.';
  return {status,message,allowSourceAttempt:status===404};
}
export function validResumedWorkspace(value: EditingWorkspace,id:string,reviewId: number|null|undefined) {
  return value.id===id&&value.reviewId===reviewId&&Number.isSafeInteger(value.revision)&&value.revision>0&&Number.isFinite(Date.parse(value.expiresAt));
}
