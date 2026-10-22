import type { RiskAssessment, RiskFinding, RiskPriority, SemanticCandidate, Vulnerability } from './securityReview';
import type { GitHubSourceMetadata } from './githubSource';

export type ProgressChange = 'RESOLVED' | 'REMAINING' | 'NEW' | 'CHANGED' | 'UNAVAILABLE';
export interface ProgressAssessment {
  deploymentAssessment: RiskAssessment['prioritizedDeploymentAssessment'];
  prioritySummary: Record<RiskPriority, number>;
  semanticCandidateCount: number;
  referenceSecurityScore: number;
}
export interface ProgressFinding { risk: RiskFinding; code: Vulnerability | null }
export interface ProgressEntry {
  fingerprint: string; status: ProgressChange; before: ProgressFinding | null; after: ProgressFinding | null;
  currentVersions: string[]; note: string;
}
export interface ReviewProgressSnapshot {
  workspaceScan?: WorkspaceScanSnapshot | null;
  sourceBefore?: GitHubSourceMetadata | null;
  sourceAfter?: GitHubSourceMetadata | null;
  comparisonSchemaVersion: number; projectId: number; baselineReviewId: number | null; currentReviewId: number;
  baselineAnalyzedAt: string | null; currentAnalyzedAt: string; generatedAt: string;
  status: 'COMPLETE' | 'PARTIAL' | 'UNAVAILABLE' | 'NO_BASELINE'; message: string;
  assessmentBefore: ProgressAssessment | null; assessmentAfter: ProgressAssessment | null;
  counts: Record<ProgressChange, number>; findings: ProgressEntry[];
  aiChanges: { fingerprint: string; status: 'REMAINING' | 'NEW' | 'NOT_REOBSERVED' | 'UNAVAILABLE';
    before: SemanticCandidate | null; after: SemanticCandidate | null; note: string }[];
  notices: string[];
}
export interface WorkspaceScanSnapshot {
  schemaVersion: number; workspaceId: string; userId: number; originalReviewId: number; revision: number;
  sourceRevision: string; identityStatus: string; inputHash: string; capturedAt: string;
  analyzerVersion: string | null; baselineVerified: boolean;
  analysisRoot?: string | null;
  files: { fileId: string; path: string; originalHash: string; currentHash: string; changed: boolean; changeOrigin: string }[];
}
