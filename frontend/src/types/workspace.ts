import type { ReviewHistoryResponse, ReviewSourceType, ReviewProgressSnapshot } from './securityReview';

export interface ProjectDetail {
  projectId: number;
  name: string;
  sourceType: ReviewSourceType;
  repositoryUrl: string | null;
  reviewCount: number;
  latestReview: ReviewHistoryResponse | null;
  createdAt: string;
  updatedAt: string;
}

export interface WorkspaceProject extends ProjectDetail {
  latestProgress: Pick<ReviewProgressSnapshot, 'status' | 'baselineReviewId' | 'counts' | 'message'> | null;
}

export interface WorkspaceResponse {
  projectCount: number;
  blockedProjectCount: number;
  reviewRequiredProjectCount: number;
  analyzedProjectCount: number;
  unassessedProjectCount: number;
  projects: WorkspaceProject[];
}
