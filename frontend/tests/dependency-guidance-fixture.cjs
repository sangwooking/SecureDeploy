module.exports = function dependencyFixture(sourceType = 'ZIP') {
  const result = require('./result-fixture.cjs')();
  result.sourceType = sourceType;
  result.projectName = '라이브러리 확인 테스트';
  const base = { ...result.riskAssessment.dependencyFindings[0], advisoryId: null, dependency: null,
    priority: 'REVIEW_REQUIRED', reasonCode: 'UNRESOLVED_VERSION', dependencyFacts: null,
    priorityReason: '정적 분석에서 이름 또는 버전을 결정하지 못했습니다.' };
  const known = { ...base, findingId: 'unresolved:MAVEN|org.example:library|null', ecosystem: 'MAVEN',
    packageName: 'org.example:library', version: null, sourceFiles: ['backend/pom.xml'] };
  const unknown = { ...base, findingId: 'unresolved:MAVEN|<unresolved-package>|null', ecosystem: 'MAVEN',
    packageName: '<unresolved-package>', version: null, sourceFiles: ['flutter_app/android/app/build.gradle.kts'] };
  result.riskAssessment.reviewRequirements = [known, unknown];
  result.riskAssessment.prioritySummary.REVIEW_REQUIRED = 2;
  result.sca.components = [known, unknown].map(f => ({ ecosystem: f.ecosystem, packageName: f.packageName,
    version: f.version, sourceFile: f.sourceFiles[0], versionResolution: 'UNRESOLVED', line: 4, direct: true, scope: 'compile' }));
  result.remediation.findings.push({ ...result.remediation.findings[0], findingId: unknown.findingId,
    advice: { ...result.remediation.findings[0].advice, recommendedAction: '<unresolved-package> 최신 버전 99.99.99로 변경하세요.',
      summary: 'unknown null N/A', codeExample: 'invented-package', configurationExample: null } });
  return result;
};
