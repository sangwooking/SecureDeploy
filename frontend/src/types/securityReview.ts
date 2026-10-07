
export interface AuthUser {
  id: number;
  email: string;
  name: string;
}

export interface AuthResponse {
  accessToken: string;
  tokenType: 'Bearer';
  user: AuthUser;
}

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type RuleCategory =
  | 'SECRET_MANAGEMENT'
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'DATABASE'
  | 'CONFIGURATION'
  | 'INPUT_VALIDATION'
  | 'FRONTEND_SECURITY'
  | 'CLIENT_SECRET_EXPOSURE'
  | 'CLIENT_STORAGE'
  | 'CLIENT_XSS'
  | 'CLIENT_REDIRECT'
  | 'DEPENDENCY'
  | 'DEVOPS_SECURITY'
  | 'CONTAINER_SECURITY'
  | 'CI_CD_SECURITY'
  | 'KUBERNETES_SECURITY';

export type ReviewSourceType = 'ZIP' | 'GITHUB';

export interface DeleteResponse {
  message: string;
}

export type VulnerabilityStatus = 'UNCHECKED' | 'ACKNOWLEDGED' | 'IN_PROGRESS' | 'RESOLVED' | 'IGNORED';

export type AiFeatureType = 'VULNERABILITY_REVIEW' | 'PROJECT_SUMMARY' | 'REMEDIATION_SUGGESTION' | 'SECURITY_AUDIT' | 'COMPARISON_INSIGHT' | 'PRIORITY_PLANNING' | 'SECURITY_ROADMAP';

export type AiConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type FalsePositiveRisk = 'LOW' | 'MEDIUM' | 'HIGH';
export type DetectionConfidence = 'LOW' | 'MEDIUM' | 'HIGH';

export interface Vulnerability {
  vulnerabilityId?: number | null;
  ruleId: string;
  category: RuleCategory;
  severity: Severity;
  filePath: string;
  line: number;
  message: string;
  recommendation: string;
  evidence?: string;
  falsePositiveRisk?: FalsePositiveRisk;
  confidence?: DetectionConfidence;
  analysisNote?: string | null;
  status?: VulnerabilityStatus;
  statusUpdatedAt?: string | null;
  statusComment?: string | null;
}

export interface SecurityReviewResponse {
  reviewId?: number;
  projectId?: number | null;
  projectName: string;
  scannedFileCount: number;
  vulnerabilityCount: number;
  securityScore: number;
  deploymentStatus: string;
  vulnerabilities: Vulnerability[];
  sca?: ScaResult | null;
  deploymentAssessmentScope?: 'RULE_ENGINE_ONLY';
  riskAssessment?: RiskAssessment | null;
  assessmentInterpretation?: {
    primaryAssessmentField: string;
    primaryAssessmentAvailable: boolean;
    securityScoreRole: 'RULE_ENGINE_REFERENCE_ONLY';
    legacyDeploymentStatusRole: 'LEGACY_RULE_ENGINE_REFERENCE';
    securityScoreDeterminesDeployment: false;
    message: string;
  };
}

export type RiskPriority = 'BLOCKING' | 'SHOULD_FIX' | 'REVIEW_REQUIRED' | 'INFORMATIONAL';
export type RiskSource = 'CODE' | 'DEPENDENCY' | 'ANALYSIS';
export type AssessmentCompletion = 'COMPLETE' | 'PARTIAL' | 'FAILED' | 'NOT_INCLUDED' | 'UNKNOWN';

export interface RiskFinding {
  findingId: string;
  source: RiskSource;
  findingCategory: 'CODE' | 'SECRET' | 'DEPENDENCY' | 'CONFIG' | 'CONTAINER' | 'IAC' | 'CI_CD' | 'ANALYSIS';
  vulnerabilityId: number | null;
  ruleId: string | null;
  ecosystem: string | null;
  packageName: string | null;
  version: string | null;
  advisoryId: string | null;
  sourceFiles: string[];
  priority: RiskPriority;
  reasonCode: string;
  priorityReason: string;
  dependencyFacts: {
    exactVersion: boolean;
    lookupConfirmed: boolean;
    direct: boolean | null;
    scopes: string[];
    fixedVersionAvailable: boolean;
    cvssScore: number | null;
  } | null;
  dependency?: DependencyVulnerability | null;
}

export interface DependencyCorrelation {
  vulnerabilityId: number | null;
  ruleId: string;
  filePath: string;
  line: number;
  observation: { source: string; ecosystem: string; packageName: string; version: string; advisoryId: string | null };
  relation: 'SAME_ADVISORY' | 'PACKAGE_CANDIDATE_CONTEXT' | 'REPEATED_CATALOG_OBSERVATION';
  canonicalFindingIds: string[];
  reason: string;
}

export interface RiskAssessment {
  schemaVersion: number;
  policyVersion: string;
  assessedAt: string;
  assessmentScope: 'RULE_ENGINE_AND_SCA';
  prioritizedDeploymentAssessment: 'BLOCKED' | 'REVIEW_REQUIRED' | 'READY_WITH_WARNINGS' | 'READY';
  assessmentReason: string;
  assessmentCoverage: {
    overall: AssessmentCompletion;
    ruleEngine: AssessmentCompletion;
    sca: AssessmentCompletion;
    ai: AssessmentCompletion;
    scopeNote: string;
  };
  prioritySummary: Record<RiskPriority, number>;
  prioritySummaryBySource: Record<RiskSource, Record<RiskPriority, number>>;
  codeFindings: RiskFinding[];
  dependencyFindings: RiskFinding[];
  reviewRequirements: RiskFinding[];
  dependencyCorrelations?: DependencyCorrelation[];
}

export interface DependencyComponent {
  ecosystem: 'MAVEN' | 'NPM';
  packageName: string;
  version: string | null;
  scope: string;
  direct: boolean | null;
  sourceFile: string;
  line: number;
  versionResolution: 'EXACT' | 'RANGE' | 'UNRESOLVED';
}

export interface DependencyVulnerability {
  ecosystem: 'MAVEN' | 'NPM';
  packageName: string;
  installedVersion: string;
  osvId: string;
  aliases: string[];
  summary: string | null;
  severity: Severity | null;
  cvssScore: number | null;
  cvssVectors: string[];
  fixedVersions: string[];
  published: string | null;
  modified: string | null;
  referenceUrls: string[];
  sourceFiles: string[];
}

export interface ScaResult {
  schemaVersion: number;
  status: 'COMPLETE' | 'PARTIAL' | 'UNAVAILABLE' | 'NO_MANIFEST' | 'DISABLED';
  analyzedAt: string;
  summary: {
    dependenciesDiscovered: number;
    dependenciesAnalyzed: number;
    unresolvedDependencies: number;
    vulnerableDependencies: number;
    dependencyVulnerabilities: number;
    severityCounts: Record<string, number>;
  };
  components: DependencyComponent[];
  dependencyVulnerabilities: DependencyVulnerability[];
  warnings: string[];
}

export interface VulnerabilityStatusResponse extends Vulnerability {
  vulnerabilityId: number;
  status: VulnerabilityStatus;
  statusUpdatedAt: string;
  statusComment?: string | null;
}

export interface VulnerabilityStatusSummaryResponse {
  projectId: number;
  total: number;
  unchecked: number;
  acknowledged: number;
  inProgress: number;
  resolved: number;
  ignored: number;
  resolvedCount: number;
  resolutionRate: number;
}

export interface DashboardScoreHistoryItem {
  reviewId: number;
  securityScore: number;
  vulnerabilityCount: number;
  createdAt: string;
}

export interface DashboardRecentHighRiskVulnerability {
  vulnerabilityId: number;
  ruleId: string;
  severity: Severity;
  category: RuleCategory;
  filePath: string;
  line: number;
  status: VulnerabilityStatus;
  message: string;
}

export interface DashboardComparisonSummary {
  previousReviewId?: number | null;
  latestReviewId?: number | null;
  scoreDiff: number;
  vulnerabilityCountDiff: number;
  resolvedCount: number;
  newCount: number;
  persistedCount: number;
  message: string;
}

export interface ProjectSecurityDashboardResponse {
  projectId: number;
  projectName: string;
  sourceType: ReviewSourceType;
  repositoryUrl?: string | null;
  createdAt: string;
  updatedAt: string;
  latestReviewId?: number | null;
  latestAnalyzedAt?: string | null;
  latestSecurityScore?: number | null;
  latestDeploymentStatus?: string | null;
  latestScannedFileCount?: number | null;
  latestVulnerabilityCount?: number | null;
  scoreHistory: DashboardScoreHistoryItem[];
  severityCounts: Record<Severity, number>;
  statusCounts: Record<VulnerabilityStatus, number>;
  resolutionRate: number;
  recentHighRiskVulnerabilities: DashboardRecentHighRiskVulnerability[];
  comparisonSummary?: DashboardComparisonSummary | null;
}

export interface ReviewHistoryResponse {
  reviewId: number;
  projectId?: number | null;
  projectName: string;
  sourceType: ReviewSourceType;
  repositoryUrl?: string | null;
  scannedFileCount: number;
  vulnerabilityCount: number;
  securityScore: number;
  deploymentStatus: string;
  createdAt: string;
}

export interface AiUsageResponse {
  provider: 'TEMPLATE' | 'OPENAI';
  featureType: AiFeatureType;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  estimatedCostUsd: number;
  billable: boolean;
  trackedAt: string;
}

export interface AiReviewResponse {
  ruleId: string;
  title: string;
  description: string;
  riskExplanation: string;
  attackScenario: string;
  recommendation: string;
  priority: string;
}

export interface AiReviewResultResponse {
  reviewId: number;
  generatedAt: string;
  reviews: AiReviewResponse[];
  usage?: AiUsageResponse;
}

export interface AiProjectSummaryResponse {
  reviewId: number;
  generatedAt: string;
  overallSecurityStatus: string;
  mostRiskyArea: string;
  priorityFixes: string[];
  preDeploymentActions: string[];
  deploymentOpinion: string;
  usage?: AiUsageResponse;
}

export interface AiRemediationResponse {
  ruleId: string;
  severity: Severity;
  category: RuleCategory;
  filePath: string;
  line: number;
  title: string;
  beforeExample: string;
  afterExample: string;
  explanation: string;
  verification: string;
}

export interface AiRemediationResultResponse {
  reviewId: number;
  generatedAt: string;
  remediations: AiRemediationResponse[];
  usage?: AiUsageResponse;
}

export interface AiSecurityAuditFindingResponse {
  title: string;
  riskArea: RuleCategory;
  severity: Severity;
  reasoning: string;
  possibleImpact: string;
  recommendation: string;
  confidence: AiConfidence;
}

export interface AiSecurityAuditResponse {
  reviewId: number;
  generatedAt: string;
  referencedFiles: string[];
  findings: AiSecurityAuditFindingResponse[];
  usage?: AiUsageResponse;
}


export interface ComparedVulnerabilityResponse {
  ruleId: string;
  category: RuleCategory;
  severity: Severity;
  filePath: string;
  line: number;
  message: string;
  recommendation: string;
  evidence?: string;
  falsePositiveRisk?: FalsePositiveRisk;
  confidence?: DetectionConfidence;
  analysisNote?: string | null;
}

export interface ReviewComparisonResponse {
  projectId: number;
  latestReviewId?: number | null;
  previousReviewId?: number | null;
  latestSecurityScore: number;
  previousSecurityScore: number;
  scoreDiff: number;
  latestVulnerabilityCount: number;
  previousVulnerabilityCount: number;
  vulnerabilityCountDiff: number;
  message: string;
  resolvedVulnerabilities: ComparedVulnerabilityResponse[];
  newVulnerabilities: ComparedVulnerabilityResponse[];
  persistedVulnerabilities: ComparedVulnerabilityResponse[];
}

export interface AiComparisonInsightResponse {
  projectId: number;
  latestReviewId?: number | null;
  previousReviewId?: number | null;
  overallInsight: string;
  improvementSummary: string;
  remainingRiskSummary: string;
  newRiskSummary: string;
  deploymentReadinessOpinion: string;
  nextRecommendedActions: string[];
  usage?: AiUsageResponse;
}

export interface AiPriorityItemResponse {
  rank: number;
  ruleId: string;
  title: string;
  severity: Severity;
  reason: string;
  expectedImpact: string;
  fixDifficulty: string;
  recommendedAction: string;
  urgency: string;
}

export interface AiPriorityResponse {
  reviewId: number;
  generatedAt: string;
  priorities: AiPriorityItemResponse[];
  usage?: AiUsageResponse;
}

export interface AiRoadmapActionResponse {
  title: string;
  description: string;
  relatedRuleIds: string[];
  reason: string;
  expectedBenefit: string;
}

export interface AiSecurityRoadmapResponse {
  reviewId: number;
  generatedAt: string;
  immediateActions: AiRoadmapActionResponse[];
  thisWeekActions: AiRoadmapActionResponse[];
  beforeDeploymentChecklist: AiRoadmapActionResponse[];
  longTermImprovements: AiRoadmapActionResponse[];
  usage?: AiUsageResponse;
}
