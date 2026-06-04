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
  VulnerabilityStatus,
  VulnerabilityStatusResponse,
  VulnerabilityStatusSummaryResponse,
} from '../types/securityReview';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080';

const ACCESS_TOKEN_STORAGE_KEY = 'securedeploy.accessToken';

function authHeaders(): HeadersInit {
  const accessToken = localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
}

function jsonHeaders(): HeadersInit {
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

export async function uploadZipForReview(file: File): Promise<SecurityReviewResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/api/reviews/upload`, {
    method: 'POST',
    headers: authHeaders(),
    body: formData,
  });

  return parseJsonResponse<SecurityReviewResponse>(response, '프로젝트 분석 요청에 실패했습니다.');
}

export async function reviewGithubRepository(repositoryUrl: string): Promise<SecurityReviewResponse> {
  const response = await fetch(`${API_BASE_URL}/api/reviews/github`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ repositoryUrl }),
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

async function parseJsonResponse<T>(response: Response, fallbackMessage: string): Promise<T> {
  if (!response.ok) {
    const errorBody = await response.json().catch(() => null);
    throw new Error(errorBody?.message ?? fallbackMessage);
  }

  return response.json();
}
