import type {
  AuthResponse,
  DeleteResponse,
  AiComparisonInsightResponse,
  AiPriorityResponse,
  AiProjectSummaryResponse,
  AiRemediationResultResponse,
  AiReviewResultResponse,
  AiSecurityAuditResponse,
  AiSecurityRoadmapResponse,
  ProjectSecurityDashboardResponse,
  ReviewComparisonResponse,
  ReviewHistoryResponse,
  SecurityReviewResponse,
  ScanMode,
  VulnerabilityStatus,
  VulnerabilityStatusResponse,
  VulnerabilityStatusSummaryResponse,
} from '../types/securityReview';
import type { UploadPolicy } from '../types/uploadPolicy';
import type { SupplementalDependencyRequest, SupplementalDependencyResponse } from '../types/dependencyGuidance';
import type { ProjectDetail, WorkspaceResponse } from '../types/workspace';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080';

const ACCESS_TOKEN_STORAGE_KEY = 'securedeploy.accessToken';

export async function lookupSupplementalDependency(reviewId: number, input: SupplementalDependencyRequest): Promise<SupplementalDependencyResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}/dependencies/supplemental-lookup`, {
    method: 'POST', headers: jsonHeaders(), body: JSON.stringify(input),
  });
  return parseJsonResponse<SupplementalDependencyResponse>(response, '라이브러리 정보를 확인하지 못했습니다. 잠시 후 다시 확인해 주세요.');
}

export async function fetchWorkspace(): Promise<WorkspaceResponse> {
  const response = await fetch(`${API_BASE_URL}/api/workspace`, { headers: authHeaders() });
  return parseJsonResponse<WorkspaceResponse>(response, '내 대시보드를 불러오지 못했습니다.');
}

export async function fetchProjectDetail(projectId: number): Promise<ProjectDetail> {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}`, { headers: authHeaders() });
  return parseJsonResponse<ProjectDetail>(response, '프로젝트를 불러오지 못했습니다.');
}

export async function fetchProjectReviews(projectId: number): Promise<ReviewHistoryResponse[]> {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/reviews`, { headers: authHeaders() });
  return parseJsonResponse<ReviewHistoryResponse[]>(response, '프로젝트 분석 이력을 불러오지 못했습니다.');
}

export function authHeaders(): HeadersInit {
  const accessToken = localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
}

export function jsonHeaders(): HeadersInit {
  return {
    'Content-Type': 'application/json',
    ...authHeaders(),
  };
}

export async function signup(email: string, password: string, name: string): Promise<AuthResponse> {
  const response = await fetch(`${API_BASE_URL}/api/auth/signup`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password, name }),
  });

  return parseJsonResponse<AuthResponse>(response, '회원가입에 실패했습니다.');
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });

  return parseJsonResponse<AuthResponse>(response, '로그인에 실패했습니다.');
}

export async function fetchUploadPolicy(): Promise<UploadPolicy> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/upload-policy`, { headers: authHeaders() });
  const policy = await parseJsonResponse<UploadPolicy>(response, '업로드 제한을 불러오지 못했습니다. 다시 확인해 주세요.');
  if (!Number.isSafeInteger(policy.maxZipBytes) || policy.maxZipBytes <= 0 || !policy.maxZipLabel || !policy.folderHint) {
    throw new Error('업로드 제한 정보가 올바르지 않습니다. 다시 확인해 주세요.');
  }
  return policy;
}

export async function uploadZipForReview(file: File, scanMode: ScanMode = 'STANDARD', projectId?: number): Promise<SecurityReviewResponse> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('scanMode', scanMode);

  const response = await fetch(`${API_BASE_URL}${projectId == null ? '/api/reviews' : `/api/projects/${projectId}/reviews`}/upload`, {
    method: 'POST',
    headers: authHeaders(),
    body: formData,
  });

  return parseJsonResponse<SecurityReviewResponse>(response, '프로젝트 분석 요청에 실패했습니다.');
}

export async function reviewGithubRepository(repositoryUrl: string, scanMode: ScanMode = 'STANDARD', projectId?: number): Promise<SecurityReviewResponse> {
  const response = await fetch(`${API_BASE_URL}${projectId == null ? '/api/reviews' : `/api/projects/${projectId}/reviews`}/github`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ repositoryUrl, scanMode }),
  });

  return parseJsonResponse<SecurityReviewResponse>(response, '프로젝트 분석 요청에 실패했습니다.');
}

export async function fetchReviewHistory(): Promise<ReviewHistoryResponse[]> {
  const response = await fetch(`${API_BASE_URL}/api/reviews`, { headers: authHeaders() });
  return parseJsonResponse<ReviewHistoryResponse[]>(response, '분석 이력을 불러오지 못했습니다.');
}



export async function fetchProjectDashboard(projectId: number): Promise<ProjectSecurityDashboardResponse> {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/dashboard`, { headers: authHeaders() });
  return parseJsonResponse<ProjectSecurityDashboardResponse>(response, '프로젝트 보안 대시보드를 불러오지 못했습니다.');
}

export async function fetchLatestReviewComparison(projectId: number): Promise<ReviewComparisonResponse> {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/reviews/compare-latest`, { headers: authHeaders() });
  return parseJsonResponse<ReviewComparisonResponse>(response, '최근 분석 비교 결과를 불러오지 못했습니다.');
}

export async function fetchReviewDetail(reviewId: number): Promise<SecurityReviewResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}`, { headers: authHeaders() });
  return parseJsonResponse<SecurityReviewResponse>(response, '분석 상세 결과를 불러오지 못했습니다.');
}

export async function deleteReview(reviewId: number): Promise<DeleteResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  return parseJsonResponse<DeleteResponse>(response, '분석 결과를 삭제하지 못했습니다.');
}

export async function deleteProject(projectId: number): Promise<DeleteResponse> {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  return parseJsonResponse<DeleteResponse>(response, '프로젝트를 삭제하지 못했습니다.');
}

export async function fetchAiReview(reviewId: number): Promise<AiReviewResultResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}/ai-review`, { headers: authHeaders() });
  return parseJsonResponse<AiReviewResultResponse>(response, 'AI 리뷰를 생성하지 못했습니다.');
}

export async function fetchAiProjectSummary(reviewId: number): Promise<AiProjectSummaryResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}/ai-summary`, { headers: authHeaders() });
  return parseJsonResponse<AiProjectSummaryResponse>(response, 'AI 종합 진단을 생성하지 못했습니다.');
}

export async function fetchAiRemediation(reviewId: number): Promise<AiRemediationResultResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}/ai-remediation`, { headers: authHeaders() });
  return parseJsonResponse<AiRemediationResultResponse>(response, 'AI 수정 제안을 생성하지 못했습니다.');
}

export async function fetchAiSecurityAudit(reviewId: number): Promise<AiSecurityAuditResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}/ai-audit`, { headers: authHeaders() });
  return parseJsonResponse<AiSecurityAuditResponse>(response, 'AI 보조 진단을 실행하지 못했습니다.');
}


export async function fetchAiComparisonInsight(projectId: number): Promise<AiComparisonInsightResponse> {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/reviews/compare-latest/ai`, { headers: authHeaders() });
  return parseJsonResponse<AiComparisonInsightResponse>(response, 'AI 비교 해석을 생성하지 못했습니다.');
}

export async function fetchAiPriorities(reviewId: number): Promise<AiPriorityResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}/ai-priorities`, { headers: authHeaders() });
  return parseJsonResponse<AiPriorityResponse>(response, 'AI 수정 우선순위를 생성하지 못했습니다.');
}

export async function fetchAiRoadmap(reviewId: number): Promise<AiSecurityRoadmapResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/${reviewId}/ai-roadmap`, { headers: authHeaders() });
  return parseJsonResponse<AiSecurityRoadmapResponse>(response, 'AI 보안 개선 로드맵을 생성하지 못했습니다.');
}


export async function updateVulnerabilityStatus(vulnerabilityId: number, status: VulnerabilityStatus, comment: string): Promise<VulnerabilityStatusResponse> {
  const response = await fetch(`${API_BASE_URL}/api/vulnerabilities/${vulnerabilityId}/status`, {
    method: 'PATCH',
    headers: jsonHeaders(),
    body: JSON.stringify({ status, comment }),
  });

  return parseJsonResponse<VulnerabilityStatusResponse>(response, '취약점 상태를 변경하지 못했습니다.');
}

export async function fetchVulnerabilityStatusSummary(projectId: number): Promise<VulnerabilityStatusSummaryResponse> {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/vulnerabilities/status-summary`, { headers: authHeaders() });
  return parseJsonResponse<VulnerabilityStatusSummaryResponse>(response, '취약점 상태 요약을 불러오지 못했습니다.');
}

export async function downloadReviewReport(reviewId: number): Promise<Blob> {
  return downloadPdf(`${API_BASE_URL}/api/reviews/${reviewId}/report`, 'PDF 리포트를 다운로드하지 못했습니다.');
}

export async function downloadAiReviewReport(reviewId: number): Promise<Blob> {
  return downloadPdf(`${API_BASE_URL}/api/reviews/${reviewId}/report/ai`, 'AI 리뷰 포함 PDF 리포트를 다운로드하지 못했습니다.');
}

async function downloadPdf(url: string, fallbackMessage: string): Promise<Blob> {
  const response = await fetch(url, { headers: authHeaders() });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => null);
    throw new Error(errorBody?.message ?? fallbackMessage);
  }

  return response.blob();
}

export async function parseJsonResponse<T>(response: Response, fallbackMessage: string): Promise<T> {
  if (!response.ok) {
    const errorBody = await response.json().catch(() => null);
    throw new Error(errorBody?.message ?? fallbackMessage);
  }

  return response.json();
}
