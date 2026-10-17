import type { DependencyVulnerability } from './securityReview';

export interface SupplementalDependencyRequest { findingId: string; packageName: string; version: string }
export interface SupplementalDependencyResponse {
  provenance: 'USER_PROVIDED';
  status: 'COMPLETE' | 'PARTIAL' | 'UNAVAILABLE' | 'DISABLED';
  checkedAt: string;
  ecosystem: 'MAVEN' | 'NPM' | 'PYPI';
  packageName: string;
  version: string;
  findings: DependencyVulnerability[];
}
