const resultFixture = require('./result-fixture.cjs');
module.exports = function progressFixture() {
  const result = resultFixture();
  result.projectId = 7; result.sourceType = 'ZIP'; result.createdAt = '2026-10-13T09:00:00';
  const code = { risk: result.riskAssessment.codeFindings[0], code: result.vulnerabilities[0] };
  const assessment = { deploymentAssessment: 'BLOCKED', prioritySummary: result.riskAssessment.prioritySummary,
    semanticCandidateCount: 1, referenceSecurityScore: 100 };
  result.comparison = {
    comparisonSchemaVersion: 1, projectId: 7, baselineReviewId: 100, currentReviewId: 101,
    baselineAnalyzedAt: '2026-10-12T09:00:00', currentAnalyzedAt: result.createdAt, generatedAt: result.createdAt,
    status: 'PARTIAL', message: '분석 범위가 불완전하여 일부 항목은 확인할 수 없습니다.',
    assessmentBefore: structuredClone(assessment), assessmentAfter: structuredClone(assessment),
    counts: { RESOLVED: 1, REMAINING: 1, NEW: 1, CHANGED: 1, UNAVAILABLE: 1 },
    findings: ['RESOLVED', 'REMAINING', 'NEW', 'CHANGED', 'UNAVAILABLE'].map((status, i) => ({
      fingerprint: 'synthetic-fingerprint-' + i, status,
      before: status === 'NEW' ? null : structuredClone(code), after: status === 'RESOLVED' ? null : structuredClone(code),
      currentVersions: [], note: status === 'UNAVAILABLE' ? 'OSV 조회 실패로 이번 검사에서는 확인할 수 없습니다.' : '비교 가능한 범위의 관찰 결과입니다. 완전한 안전을 보장하지 않습니다.',
    })),
    aiChanges: [{ fingerprint: 'synthetic-ai', status: 'NOT_REOBSERVED', before: result.semanticReview.candidates[0], after: null,
      note: '이번 AI 검토에서는 다시 관찰되지 않았습니다. 해결 판정이 아닙니다.' }],
    notices: ['저장된 비교입니다. 과거 데이터를 다시 평가하지 않습니다.'],
  };
  return result;
};
