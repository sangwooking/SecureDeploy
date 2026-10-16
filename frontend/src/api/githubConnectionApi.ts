import { authHeaders, jsonHeaders, parseJsonResponse } from './securityReviewApi';
import type { GitHubConnection, GitHubInstallation, ConnectedRepository } from '../types/githubConnection';
import type { ScanMode, SecurityReviewResponse } from '../types/securityReview';

const base = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080';
async function request<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch(`${base}${path}`, {
    method, headers: body ? jsonHeaders() : authHeaders(), body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store', referrerPolicy: 'no-referrer',
  });
  return parseJsonResponse<T>(response, 'GitHub 연결 요청을 완료하지 못했습니다.');
}
export const fetchGitHubConnection = () => request<GitHubConnection>('/api/github/connection');
export const beginGitHubConnection = () => request<{ authorizationUrl: string }>('/api/github/connection/authorize', 'POST');
export const completeGitHubConnection = (code: string, state: string) => request<GitHubConnection>('/api/github/connection/callback', 'POST', { code, state });
export const disconnectGitHub = () => request<{ message: string }>('/api/github/connection', 'DELETE');
export const fetchGitHubInstallations = (page = 1) => request<{ installations: GitHubInstallation[]; hasNextPage: boolean }>(`/api/github/installations?page=${page}`);
export const fetchConnectedRepositories = (installationId: number, page = 1) => request<{ repositories: ConnectedRepository[]; hasNextPage: boolean }>(`/api/github/installations/${installationId}/repositories?page=${page}`);
export const reviewConnectedRepository = (repository: Pick<ConnectedRepository, 'installationId' | 'repositoryId'>, scanMode: ScanMode, projectId?: number) =>
  request<SecurityReviewResponse>(`${projectId == null ? '/api/reviews' : `/api/projects/${projectId}/reviews`}/github/connected`, 'POST', {
    installationId: repository.installationId, repositoryId: repository.repositoryId, scanMode,
  });
