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
export interface DependencyAdviceProvider {name:string;model:string;available:boolean;origin:string;unavailableReason?:string|null}
export interface DependencyAdviceOutput {
 evidenceHash:string;packageName:string;lockedVersion:string;advisoryId:string;decision:string;candidateVersion:string;
 explanation:string;whyItMatters:string;possibleImpact:string;recommendedAction:string;verificationSteps:string[];uncertainties:string[];
}
export interface DependencyAdviceView {
 id:string;reviewId:number;planIndex:number;evidenceHash:string;state:string;provider:DependencyAdviceProvider;
 transmittedData:string;output:DependencyAdviceOutput|null;message:string;reviewStatus:string;compatibility:string;patchApplicable:boolean;modelQuality:string;expiresAt:string;
}
