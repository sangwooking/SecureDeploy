export interface GitHubSourceMetadata {
  owner: string;
  repository: string;
  canonicalRepositoryUrl: string;
  analyzedBranch: string;
  commitSha: string;
  shortCommitSha: string;
  commitTimestamp: string | null;
  cloneStartedAt: string;
  clonedAt: string;
  analyzedAt: string | null;
  cloneDepth: number;
  submoduleCount: number;
  lfsPointerCount: number;
  symlinkCount: number;
  limitations: string[];
}
