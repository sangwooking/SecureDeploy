import { authHeaders, jsonHeaders, parseJsonResponse } from './securityReviewApi';

const BASE = `${import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080'}/api/editing-workspaces`;
export interface SourceVerification {status:'VERIFIED'|'MISMATCH'|'UNAVAILABLE'|'PARTIAL'|'UNVERIFIED';message:string;scope:string;recorded:boolean;archiveSha256?:string|null;commitSha?:string|null;fileCount:number;retention?:{storageMode:'ENCRYPTED_PERSISTENT'|'MEMORY_TEMPORARY';seconds:number;maxBytes:number;maxFiles:number}}
export const loadSourceVerification=(reviewId:number)=>call<SourceVerification>(`/review/${reviewId}/source`);
export interface ChangeAttribution {revision:number;generator:string;providerOrigin?:string|null;model?:string|null;proposalId?:string|null;directionOrigin?:string|null;adviceId?:string|null;approved:boolean;userId:number;at:string;currentHash:string}
export interface EditingFile { id: string; path: string; originalHash: string; size: number; directory: boolean; editable: boolean; readOnlyReason: string | null; changed: boolean; changeOrigin?:string; provenance?:ChangeAttribution[] }
export interface EditingWorkspace { storageMode?: 'MEMORY_TEMPORARY' | 'ENCRYPTED_PERSISTENT'; id: string; reviewId: number; revision: number; createdAt: string; expiresAt: string; sourceRevision: string; identityStatus: 'UNVERIFIED_REUPLOAD' | 'EXACT_GIT_COMMIT' | 'VERIFIED_ZIP_MANIFEST' | 'PARTIAL_ZIP_MANIFEST'; sourceVerification?:SourceVerification; files: EditingFile[]; changedFileIds: string[]; exports?:{revision:number;format:string;userId:number;at:string;provenanceHash:string}[] }
export interface EditingContent { fileId: string; revision: number; originalHash: string; currentHash: string; text: string; newline: 'LF' | 'CRLF'; bom: boolean }
export interface EditingDiff { revision: number; fileId: string; originalHash: string; patch: string; changeOrigin?:string; provenance?:ChangeAttribution[] }
async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${BASE}${path}`, { cache: 'no-store', ...init, headers: init.headers ?? authHeaders() });
  return parseJsonResponse<T>(response, '수정 작업 공간 요청을 처리하지 못했습니다.');
}
export async function createEditingWorkspace(reviewId: number, file?: File): Promise<EditingWorkspace> {
  if (file) { const form = new FormData(); form.append('file', file); return call(`/zip/${reviewId}?sourceRetentionAcknowledged=true`, { method: 'POST', body: form }); }
  return call(`/github/${reviewId}?sourceRetentionAcknowledged=true`, { method: 'POST' });
}
export interface WorkspaceDiscovery {state:'AVAILABLE'|'NONE'|'OTHER_REVIEW'|'CREATING';workspace:EditingWorkspace|null}
export const discoverEditingWorkspace=(reviewId:number)=>call<WorkspaceDiscovery>(`/review/${reviewId}/active`);
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
export interface PatchProvider { origin?:string; name: string; model: string; available: boolean }
export interface AiPatch { contextHash?:string|null; usage?:{model?:string;promptTokens:number;completionTokens:number;cachedInputTokens:number;usageKnown:boolean;estimatedCostUsd:number|null;costStatus:string;billable:boolean}|null; id: string; state: string; fileId: string; findingId: number; ruleId: string; reviewId: number;
  sourceRevision: string; revision: number; originalHash: string; currentHash: string; startLine: number;
  context?: {code:string;startLine:number;endLine:number;endpoint:string;sources:{line:number;column:number}[];sink:{line:number;column:number};removedFields:string[];preservedFields:string[];bindings?:{sourceId:string;findingId:string;field:string;source:{line:number;column:number};sink:{line:number;column:number};startOffset:number;endOffset:number;expressionHash:string}[]}|null; before: string; after: string | null; diff: string | null; provider: PatchProvider; explanation: string;
  verificationSteps: string[]; limitations: string[]; flowFindingId?: string | null; plan?:{version:string;objectId:string;revision:number;originalHash:string;requiredFields:{fieldId:string;field:string;sourceId:string}[]}|null; method?: 'AI_ASSISTED' | 'DETERMINISTIC_FIX' | 'AI_PLAN_SERVER_AST' }
export interface FixOption { supportLevel?: 'VERIFIED_AUTO_FIX' | 'AI_ASSISTED_FIX' | 'GUIDED_REMEDIATION' | 'REVIEW_ONLY' | 'UNSUPPORTED'; method: 'DETERMINISTIC_FIX' | 'AI_ASSISTED' | 'MANUAL_REVIEW' | 'UNSUPPORTED'; reason: string }
export const fixOption = (w: EditingWorkspace, file: EditingFile, content: EditingContent, findingId: number, flowFindingId?: string) => call<FixOption>(`/${encodeURIComponent(w.id)}/fix-options`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ fileId: file.id, findingId, flowFindingId, revision: w.revision, originalHash: file.originalHash, currentHash: content.currentHash }),
});
export const prepareDeterministicPatch = (w: EditingWorkspace, file: EditingFile, content: EditingContent, flowFindingId: string) => call<AiPatch>(`/${encodeURIComponent(w.id)}/deterministic-patches`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ fileId: file.id, findingId: 0, flowFindingId, revision: w.revision, originalHash: file.originalHash, currentHash: content.currentHash }),
});
export const prepareAiPatchPlan = (w:EditingWorkspace,file:EditingFile,content:EditingContent,flowFindingId:string)=>call<AiPatch>(`/${encodeURIComponent(w.id)}/patch-plans`,{method:'POST',headers:jsonHeaders(),body:JSON.stringify({fileId:file.id,findingId:0,flowFindingId,revision:w.revision,originalHash:file.originalHash,currentHash:content.currentHash})});
export const patchProvider = () => call<PatchProvider>('/patch-provider');
export const listAiPatches = (id: string) => call<AiPatch[]>(`/${encodeURIComponent(id)}/patches`);
export const prepareAiPatch = (w: EditingWorkspace, file: EditingFile, content: EditingContent, findingId: number, flowFindingId?: string) => call<AiPatch>(`/${encodeURIComponent(w.id)}/patches`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ fileId: file.id, findingId, flowFindingId, revision: w.revision, originalHash: file.originalHash, currentHash: content.currentHash }),
});
export const generateAiPatch = (id: string, p: AiPatch) => call<AiPatch>(`/${encodeURIComponent(id)}/patches/${encodeURIComponent(p.id)}/generate`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ revision: p.revision, currentHash: p.currentHash, consented: true, contextHash: p.contextHash }),
});
export const rejectAiPatch = (id: string, proposal: string) => call<AiPatch>(`/${encodeURIComponent(id)}/patches/${encodeURIComponent(proposal)}/reject`, { method: 'POST' });
export const applyAiPatch = (id: string, p: AiPatch) => call<EditingWorkspace>(`/${encodeURIComponent(id)}/patches/${encodeURIComponent(p.id)}/apply`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ revision: p.revision, currentHash: p.currentHash, approved: true, responseContractAcknowledged: !!p.flowFindingId }),
});
export interface WorkspaceScan { id: string; state: 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'TIMED_OUT'; workspaceId: string;
  revision: number; inputHash: string; reviewId: number | null; message: string; capturedAt: string }
export const startWorkspaceScan = (w: EditingWorkspace) => call<WorkspaceScan>(`/${encodeURIComponent(w.id)}/scans`, {
  method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ revision: w.revision, changedFileIds: w.changedFileIds, approved: true, externalLookupAcknowledged: true }),
});
export const loadWorkspaceScan = (id: string) => call<WorkspaceScan>(`/scans/${encodeURIComponent(id)}`);

export interface WorkspaceSemanticReview {id:string;state:string;inputHash:string;revision:number;origin:string;available:boolean;model:string;transmittedData:string;selectedContexts:number;omittedContexts:number;result:import('../types/securityReview').SemanticSnapshot|null;limitations:string[]}
export const prepareWorkspaceSemantic=(w:EditingWorkspace)=>call<WorkspaceSemanticReview>(`/${w.id}/semantic-review`,{method:'POST',headers:jsonHeaders(),body:JSON.stringify({revision:w.revision})});
export const generateWorkspaceSemantic=(w:EditingWorkspace,p:WorkspaceSemanticReview)=>call<WorkspaceSemanticReview>(`/${w.id}/semantic-review/${p.id}/generate`,{method:'POST',headers:jsonHeaders(),body:JSON.stringify({inputHash:p.inputHash,approved:true})});
export interface DependencyFilesProposal {id:string;state:string;revision:number;inputHash:string;adviceId:string;origin:string;packageName:string;fromVersion:string;toVersion:string;executionEnabled:boolean;differences:{path:string;fileId:string;originalHash:string;currentHash:string;proposedHash:string;patch:string}[];changedPackages:string[];message:string}
export const prepareDependencyFiles=(w:EditingWorkspace,adviceId:string)=>call<DependencyFilesProposal>(`/${w.id}/dependency-files`,{method:'POST',headers:jsonHeaders(),body:JSON.stringify({revision:w.revision,adviceId})});
export const generateDependencyFiles=(w:EditingWorkspace,p:DependencyFilesProposal)=>call<DependencyFilesProposal>(`/${w.id}/dependency-files/${p.id}/generate`,{method:'POST',headers:jsonHeaders(),body:JSON.stringify({inputHash:p.inputHash,approved:true})});
export const applyDependencyFiles=(w:EditingWorkspace,p:DependencyFilesProposal)=>call<EditingWorkspace>(`/${w.id}/dependency-files/${p.id}/apply`,{method:'POST',headers:jsonHeaders(),body:JSON.stringify({inputHash:p.inputHash,approved:true})});
