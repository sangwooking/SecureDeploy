import { authHeaders, jsonHeaders, parseJsonResponse } from './securityReviewApi';

const BASE = `${import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080'}/api/editing-workspaces`;
export interface EditingFile { id: string; path: string; originalHash: string; size: number; directory: boolean; editable: boolean; readOnlyReason: string | null; changed: boolean }
export interface EditingWorkspace { id: string; reviewId: number; revision: number; createdAt: string; expiresAt: string; sourceRevision: string; identityStatus: 'UNVERIFIED_REUPLOAD' | 'EXACT_GIT_COMMIT'; files: EditingFile[]; changedFileIds: string[] }
export interface EditingContent { fileId: string; revision: number; originalHash: string; text: string; newline: 'LF' | 'CRLF'; bom: boolean }
export interface EditingDiff { revision: number; fileId: string; originalHash: string; patch: string }
async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${BASE}${path}`, { cache: 'no-store', ...init, headers: init.headers ?? authHeaders() });
  return parseJsonResponse<T>(response, '수정 작업 공간 요청을 처리하지 못했습니다.');
}
export async function createEditingWorkspace(reviewId: number, file?: File): Promise<EditingWorkspace> {
  if (file) { const form = new FormData(); form.append('file', file); return call(`/zip/${reviewId}`, { method: 'POST', body: form }); }
  return call(`/github/${reviewId}`, { method: 'POST' });
}
export const loadEditingWorkspace = (id: string) => call<EditingWorkspace>(`/${encodeURIComponent(id)}`);
export const loadEditingFile = (id: string, file: string) => call<EditingContent>(`/${encodeURIComponent(id)}/files/${encodeURIComponent(file)}`);
export const loadEditingDiff = (id: string, file: string) => call<EditingDiff>(`/${encodeURIComponent(id)}/files/${encodeURIComponent(file)}/diff`);
export const deleteEditingWorkspace = (id: string) => call(`/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const saveEditingFile = (workspace: EditingWorkspace, file: EditingFile, text: string, revert = false) => call<EditingWorkspace>(
  `/${encodeURIComponent(workspace.id)}/files/${encodeURIComponent(file.id)}${revert ? '/revert' : ''}`, {
    method: revert ? 'POST' : 'PUT', headers: jsonHeaders(), body: JSON.stringify({ revision: workspace.revision, originalHash: file.originalHash, text }),
  });
export async function exportEditingWorkspace(workspace: EditingWorkspace, format: 'zip' | 'patch'): Promise<Blob> {
  const response = await fetch(`${BASE}/${encodeURIComponent(workspace.id)}/export/${format}`, {
    method: 'POST', cache: 'no-store', headers: jsonHeaders(), body: JSON.stringify({ revision: workspace.revision, changedFileIds: workspace.changedFileIds, approved: true }),
  });
  if (!response.ok) { const error = await response.json().catch(() => null); throw new Error(error?.message ?? '수정본을 다운로드하지 못했습니다.'); }
  return response.blob();
}
