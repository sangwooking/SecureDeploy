export interface DependencyUpdatePlan {
  ecosystem: string; packageName: string; lockedVersion: string; advisoryId: string; aliases: string[];
  sourceFiles: string[]; advisoryModified: string | null; dependencyKind: string;
  locations: {file: string; line: number; section: string; parentPackage: string; declaredVersion: string; confirmed: boolean; optional: boolean; peer: boolean}[];
  fixedVersionEvidence: string[]; sameMajorCandidates: string[]; packageManagerEvidence: string; action: string;
  status: string; patchApplicable: boolean; compatibility: string; lockfileStatus: string;
  explanation: string; verificationSteps: string[]; unknowns: string[];
}
export interface DependencyUpdatePlans {
  schemaVersion: number; reviewId: number; sourceRevision: string | null; analyzedAt: string | null;
  evidenceHash: string; origin: string; modelVerification: string; plans: DependencyUpdatePlan[]; limitations: string[];
}
