export interface AnalysisLocation { filePath: string; line: number; column?: number; functionName: string; kind: string }
export interface ServerAnalysisSnapshot {
  schemaVersion: number;
  analyzerVersion: string;
  parserVersion: string | null;
  status: string;
  files: { filePath: string; parseStatus: string; flowStatus: string; entrypoints: number; functionsAnalyzed: number;
    prepareCallSites?: number; tracedPrepareCallSites?: number; limitations: string[] }[];
  findings: { ruleId: string; kind: string; confidence: string; disposition: string;
    source: AnalysisLocation; sink: AnalysisLocation; flow: AnalysisLocation[]; defenses: AnalysisLocation[];
    limitations: string[]; message: string; recommendation: string }[];
  sqlUses: { kind: string; location: AnalysisLocation; trace: AnalysisLocation[]; defenses: AnalysisLocation[];
    limitations: string[]; executionObserved: boolean }[];
  authorizationContexts: { entry: AnalysisLocation; checks: AnalysisLocation[]; defenses: AnalysisLocation[];
    resources: AnalysisLocation[]; conclusion: string; limitations: string[] }[];
  limitations: string[];
}
