import { authHeaders, jsonHeaders, parseJsonResponse } from './securityReviewApi';

const BASE = `${import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080'}/api/editing-workspaces`;
export interface EditingFile { id: string; path: string; originalHash: string; size: number; directory: boolean; editable: boolean; readOnlyReason: string | null; changed: boolean }
export interface EditingWorkspace { id: string; reviewId: number; revision: number; createdAt: string; expiresAt: string; sourceRevision: string; identityStatus: 'UNVERIFIED_REUPLOAD' | 'EXACT_GIT_COMMIT'; files: EditingFile[]; changedFileIds: string[] }
export interface EditingContent { fileId: string; revision: number; originalHash: string; currentHash: string; text: string; newline: 'LF' | 'CRLF'; bom: boolean }
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
export interface PatchProvider { name: string; model: string; available: boolean }
export interface AiPatch { id: string; state: string; fileId: string; findingId: number; ruleId: string; reviewId: number;
  sourceRevision: string; revision: number; originalHash: string; currentHash: string; startLine: number;
  before: string; after: string | null; diff: string | null; provider: PatchProvider; explanation: string;
  verificationSteps: string[]; limitations: string[] }
export const patchProvider = () => call<PatchProvider>('/patch-provider');
export const listAiPatches = (id: string) => call<AiPatch[]>(`/${encodeURIComponent(id)}/patches`);
export const prepareAiPatch = (w: EditingWorkspace, file: EditingFile, content: EditingContent, findingId: number) => call<AiPatch>(`/${encodeURIComponent(w.id)}/patches`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ fileId: file.id, findingId, revision: w.revision, originalHash: file.originalHash, currentHash: content.currentHash }),
});
export const generateAiPatch = (id: string, p: AiPatch) => call<AiPatch>(`/${encodeURIComponent(id)}/patches/${encodeURIComponent(p.id)}/generate`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ revision: p.revision, currentHash: p.currentHash, consented: true }),
});
export const rejectAiPatch = (id: string, proposal: string) => call<AiPatch>(`/${encodeURIComponent(id)}/patches/${encodeURIComponent(proposal)}/reject`, { method: 'POST' });
export const applyAiPatch = (id: string, p: AiPatch) => call<EditingWorkspace>(`/${encodeURIComponent(id)}/patches/${encodeURIComponent(p.id)}/apply`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ revision: p.revision, currentHash: p.currentHash, approved: true }),
});
export interface WorkspaceScan { id: string; state: 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'TIMED_OUT'; workspaceId: string;
  revision: number; inputHash: string; reviewId: number | null; message: string; capturedAt: string }
export const startWorkspaceScan = (w: EditingWorkspace) => call<WorkspaceScan>(`/${encodeURIComponent(w.id)}/scans`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ revision: w.revision, changedFileIds: w.changedFileIds, approved: true, externalLookupAcknowledged: true }),
});
export const loadWorkspaceScan = (id: string) => call<WorkspaceScan>(`/scans/${encodeURIComponent(id)}`);
