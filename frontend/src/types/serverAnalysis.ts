export interface AnalysisLocation { filePath: string; line: number; column?: number; functionName: string; kind: string }
export interface AuthorizationDetails {
  authenticationStatus: string; objectAuthorizationStatus: string; permissionSource: string;
  permissionDeclarations: { source: string; permissions: string[]; location: AnalysisLocation }[];
  principalReferences: AnalysisLocation[]; ownershipComparisons: AnalysisLocation[];
  accesses: { operation: string; location: AnalysisLocation; resourceLocation: AnalysisLocation; identifierInputs: AnalysisLocation[];
    checks: AnalysisLocation[]; conclusion: string; limitations: string[] }[];
  limitations: string[];
}
export interface ServerFlowFinding {
  findingId: string; sourceType: 'TYPESCRIPT_DATA_FLOW' | 'PYTHON_DATA_FLOW'; analyzerVersion: string; ruleId: string;
  priority: 'REVIEW_REQUIRED'; comparisonPolicy: 'NOT_COMPARED'; location: AnalysisLocation;
  evidence: ServerAnalysisSnapshot['findings']; executionLocations: AnalysisLocation[];
  title: string; riskExplanation: string; recommendedAction: string; verificationSteps: string[];
}
export interface ServerAnalysisSnapshot {
  exposureUses?: { kind: string; status: string; location: AnalysisLocation; trace: AnalysisLocation[]; limitations: string[] }[] | null;
  tokenUses?: { operation: string; location: AnalysisLocation; signatureStatus: string; keySource: string;
    usageStatus: string; trace: AnalysisLocation[]; limitations: string[] }[] | null;
  deploymentAnalysis?: import('./deploymentAnalysis').DeploymentAnalysis | null;
  pythonAnalysis?: ServerAnalysisSnapshot | null;
  selectionCoverage?: { discoveredFiles: number; submittedFiles: number; omittedFiles: number; omittedDetails: number;
    submittedCharacters: number; omissionReasons: Record<string, number> } | null;
  schemaVersion: number;
  analyzerVersion: string;
  parserVersion: string | null;
  status: string;
  files: { filePath: string; parseStatus: string; flowStatus: string; entrypoints: number; functionsAnalyzed: number;
    prepareCallSites?: number; tracedPrepareCallSites?: number; httpCallSites?: number | null; tracedHttpCallSites?: number | null;
    selectionReason?: string | null; resourceCallSites?: number | null; tracedResourceCallSites?: number | null; limitations: string[] }[];
  findings: { ruleId: string; kind: string; confidence: string; disposition: string;
    source: AnalysisLocation; sink: AnalysisLocation; flow: AnalysisLocation[]; defenses: AnalysisLocation[];
    limitations: string[]; message: string; recommendation: string }[];
  validatedFindings?: ServerFlowFinding[] | null;
  httpUses?: { kind: string; controlledPart: string; location: AnalysisLocation; trace: AnalysisLocation[];
    defenses: AnalysisLocation[]; limitations: string[] }[] | null;
  resourceUses?: { ruleId: string; kind: string; location: AnalysisLocation; trace: AnalysisLocation[];
    defenses: AnalysisLocation[]; limitations: string[]; executionObserved: boolean }[] | null;
  sqlUses: { kind: string; location: AnalysisLocation; trace: AnalysisLocation[]; defenses: AnalysisLocation[];
    limitations: string[]; executionObserved: boolean; executionLocations?: AnalysisLocation[] | null }[];
  authorizationContexts: { entry: AnalysisLocation; checks: AnalysisLocation[]; defenses: AnalysisLocation[];
    resources: AnalysisLocation[]; conclusion: string; limitations: string[]; details?: AuthorizationDetails | null }[];
  limitations: string[];
}
