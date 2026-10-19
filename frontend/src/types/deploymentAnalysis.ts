export interface DeploymentAnalysis {
  schemaVersion: number; analyzerVersion: string; status: string; limitations: string[];
  files: { filePath: string; format: string; status: string; limitations: string[];
    observations: { line: number; scope: string; setting: string; valueStatus: string; valueSummary: string; ruleId: string }[] }[];
  findings: { findingId: string; sourceType: string; priority: 'REVIEW_REQUIRED'; comparisonPolicy: 'NOT_COMPARED';
    filePath: string; line: number; scope: string; setting: string; ruleId: string; valueSummary: string;
    title: string; reason: string; recommendation: string; verificationSteps: string[] }[];
}
