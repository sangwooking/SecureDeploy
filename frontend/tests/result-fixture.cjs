// Entirely synthetic responses. Browser tests intercept every API request.
module.exports = function resultFixture() {
  const date = '2026-10-12T00:00:00Z';
  const counts = { BLOCKING: 1, REVIEW_REQUIRED: 1, SHOULD_FIX: 1, INFORMATIONAL: 1 };
  const dependency = { ecosystem: 'NPM', packageName: 'fixture-library', installedVersion: '1.0.0',
    osvId: 'TEST-ADVISORY-1', aliases: ['CVE-2099-0001'], summary: '테스트용 보안 공지입니다.', severity: 'HIGH',
    cvssScore: 8, cvssVectors: [], fixedVersions: ['1.0.1', '2.0.0'], published: null, modified: null,
    referenceUrls: ['https://example.invalid/advisory', 'javascript:alert(1)'], sourceFiles: ['package.json'] };
  const code = { vulnerabilityId: 51, ruleId: 'HARDCODED_SECRET', severity: 'HIGH', category: 'SECRET_MANAGEMENT',
    filePath: 'src/main/java/example/Config.java', line: 12, message: 'API Key가 코드에 포함되어 있습니다.',
    recommendation: '키를 폐기하고 새로 발급한 값을 환경변수로 관리하세요.', evidence: 'secret = <redacted>',
    confidence: 'HIGH', falsePositiveRisk: 'LOW', analysisNote: '테스트 응답의 판단 근거입니다.', status: 'UNCHECKED' };
  const riskFinding = { findingId: 'code:51', source: 'CODE', findingCategory: 'SECRET', vulnerabilityId: 51,
    ruleId: code.ruleId, ecosystem: null, packageName: null, version: null, advisoryId: null, sourceFiles: [code.filePath],
    priority: 'BLOCKING', reasonCode: 'FIXTURE_SECRET', priorityReason: '코드에 노출된 인증정보를 제거해야 합니다.', dependencyFacts: null };
  const requirement = { ...riskFinding, findingId: 'coverage:sca', source: 'ANALYSIS', findingCategory: 'ANALYSIS',
    vulnerabilityId: null, ruleId: null, priority: 'REVIEW_REQUIRED', sourceFiles: ['package.json'], priorityReason: '정확한 설치 버전을 확인하지 못했습니다.' };
  const dependencyFinding = { ...riskFinding, findingId: 'dependency:fixture', source: 'DEPENDENCY', findingCategory: 'DEPENDENCY',
    vulnerabilityId: null, ruleId: null, ecosystem: 'NPM', packageName: dependency.packageName, version: '1.0.0', advisoryId: dependency.osvId,
    priority: 'SHOULD_FIX', sourceFiles: ['package.json'], dependency, priorityReason: '호환성을 확인한 뒤 수정 버전으로 업데이트하세요.' };
  const informational = { ...riskFinding, findingId: 'code:52', vulnerabilityId: 52, ruleId: 'DEBUG_ENABLED', priority: 'INFORMATIONAL',
    findingCategory: 'CONFIG', priorityReason: '운영 환경 설정을 확인하세요.', sourceFiles: ['application.yml'] };
  const candidate = { candidateId: 'semantic:fixture', sliceId: 'slice:fixture', candidateType: 'IDOR',
    title: '다른 사용자의 계정 정보에 접근할 수 있는지 확인이 필요합니다.', semanticAnalysisConfidence: 'MEDIUM',
    reason: '검토된 코드 범위에서 소유권 검사 여부를 확인하지 못했습니다.', findingType: 'AI_SECURITY_CANDIDATE',
    verificationRequired: true, reviewStatus: 'REVIEW_REQUIRED',
    evidence: [{ contextId: 'context:fixture', filePath: 'AccountController.java', startLine: 12, endLine: 18,
      functionName: 'findAccount(long)', evidenceDescription: '서비스 호출 전후의 권한 확인이 필요합니다.' }],
    verificationSteps: ['다른 계층에서 로그인 사용자와 리소스 소유자를 비교하는지 확인하세요.'],
    relatedExistingFindingIds: [], generatedAt: date, provider: 'openai', model: 'fixture-model', promptVersion: 'fixture-v1' };
  return { reviewId: 101, projectId: 7, sourceType: 'ZIP', createdAt: date, projectName: '사용자 흐름 테스트 프로젝트', scanMode: 'AI_ENHANCED', scannedFileCount: 8,
    vulnerabilityCount: 2, securityScore: 100, deploymentStatus: '배포 가능', vulnerabilities: [code,
      { ...code, vulnerabilityId: 52, ruleId: 'DEBUG_ENABLED', message: '개발 설정 확인', category: 'CONFIGURATION',
        filePath: 'application.yml', line: 1, severity: 'LOW', confidence: 'LOW', falsePositiveRisk: 'HIGH', analysisNote: null }],
    riskAssessment: { schemaVersion: 3, policyVersion: 'fixture-v1', assessedAt: date, assessmentScope: 'RULE_ENGINE_SCA_AND_THREAT_INTELLIGENCE',
      prioritizedDeploymentAssessment: 'BLOCKED', assessmentReason: '필수 수정 사항이 있습니다.',
      assessmentCoverage: { overall: 'PARTIAL', ruleEngine: 'COMPLETE', sca: 'PARTIAL', ai: 'NOT_INCLUDED', scopeNote: '테스트 분석 범위' },
      prioritySummary: counts, prioritySummaryBySource: { CODE: counts, DEPENDENCY: counts, ANALYSIS: counts },
      codeFindings: [riskFinding, informational], dependencyFindings: [dependencyFinding], reviewRequirements: [requirement],
      dependencyCorrelations: [], threatIntelligence: null },
    sca: { schemaVersion: 1, status: 'PARTIAL', analyzedAt: date, summary: { dependenciesDiscovered: 2, dependenciesAnalyzed: 1,
      unresolvedDependencies: 1, vulnerableDependencies: 1, dependencyVulnerabilities: 1, severityCounts: { HIGH: 1 } },
      components: [{ ecosystem: 'NPM', packageName: 'unresolved-fixture', version: '^1', scope: 'dependencies', direct: true,
        sourceFile: 'package.json', line: 4, versionResolution: 'RANGE' }], dependencyVulnerabilities: [dependency], warnings: ['테스트 조회 미완료'] },
    remediation: { schemaVersion: 1, snapshotId: 'remediation:fixture', generatedAt: date, generationStatus: 'TEMPLATE',
      omittedFindingCount: 0, notices: [], usage: null, findings: [{ findingId: 'code:51', provider: 'template', model: null,
        promptVersion: 'fixture-v1', generatedAt: date, generationStatus: 'TEMPLATE', advice: {
          summary: '코드에서 인증정보 제거', whyItMatters: '공개되면 다른 사람이 인증정보를 사용할 수 있습니다.',
          recommendedAction: '키 교체 후 환경변수로 이동하세요.', codeExample: null, configurationExample: 'secret: \u0024{EXAMPLE_SECRET}',
          verificationSteps: ['수정 후 다시 검사하세요.'], caution: '기존 기능 테스트도 확인하세요.', remediationConfidence: 'MEDIUM' } }] },
    semanticReview: { schemaVersion: 1, snapshotId: 'semantic:fixture', scanMode: 'AI_ENHANCED', semanticReviewStatus: 'COMPLETED',
      candidates: [candidate], existingFindingEvidence: [], slices: [], semanticSlicesAnalyzed: 1, omittedSlices: 0, rejectedCandidates: 0,
      deduplicatedCandidates: 0, validationStatus: 'VALID', provider: 'openai', model: 'fixture-model', promptVersion: 'fixture-v1',
      generatedAt: date, requestCount: 1, usage: { totalTokens: 123 }, notices: [] } };
};
