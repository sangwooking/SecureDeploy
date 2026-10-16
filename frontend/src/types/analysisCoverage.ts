export interface CoverageLedger {
  schemaVersion: number; policyVersion: string; status: string;
  discoveredFiles: number; selectedFiles: number; unsupportedFiles: number; excludedFiles: number;
  failedFiles: number; inventoryComplete: boolean; omittedEntries: number;
  entries: { filePath: string; kind: string; fileType: string | null; status: string; reason: string }[];
  analyzers: { analyzer: string; status: string; scope: string; fileStatuses: Record<string, number> }[];
}

export interface DependencyContext {
  schemaVersion: number; environment: 'DEVELOPMENT' | 'PRODUCTION' | 'SHARED' | 'UNKNOWN';
  runtimeReachability: 'NOT_ANALYZED'; installedPath: string; lockLine: number;
  lockFlags: string[]; pathsComplete: boolean; limitations: string[];
  paths: {
    declarationFile: string; declarationLine: number; declarationSection: string;
    declaredPackage: string; declaredVersion: string | null; declarationConfirmed: boolean;
    optional: boolean; peer: boolean;
    chain: { packageName: string; version: string | null; installedPath: string }[];
  }[];
}
