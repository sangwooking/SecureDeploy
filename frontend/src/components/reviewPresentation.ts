import type { RiskAssessment, RiskFinding, RiskPriority, SecurityReviewResponse, SemanticSnapshot, Vulnerability } from '../types/securityReview';

export type ResultView = 'SUMMARY' | 'BLOCKING' | 'REVIEW_REQUIRED' | 'SHOULD_FIX' | 'GUIDANCE' | 'TECHNICAL' | 'PROGRESS';
export const resultViews: { id: ResultView; label: string }[] = [
  { id: 'SUMMARY', label: '결과 요약' }, { id: 'BLOCKING', label: '반드시 처리' },
  { id: 'REVIEW_REQUIRED', label: '배포 전 직접 확인할 부분' }, { id: 'SHOULD_FIX', label: '수정 권장' },
  { id: 'GUIDANCE', label: '해결 방법' }, { id: 'PROGRESS', label: '변화 보기' }, { id: 'TECHNICAL', label: '기술 정보' },
];
export const priorityLabels: Record<RiskPriority, string> = {
  BLOCKING: '반드시 처리', REVIEW_REQUIRED: '배포 전 직접 확인할 부분', SHOULD_FIX: '수정 권장', INFORMATIONAL: '참고 사항',
};
export const deploymentLabels: Record<RiskAssessment['prioritizedDeploymentAssessment'], string> = {
  BLOCKED: '배포 전 수정 필요', REVIEW_REQUIRED: '확인 후 배포 판단 필요',
  READY_WITH_WARNINGS: '배포 가능하지만 수정 권장', READY: '현재 분석 범위에서는 배포 가능',
};

export function allRiskFindings(result: SecurityReviewResponse): RiskFinding[] {
  const risk = result.riskAssessment;
  return risk ? [...risk.codeFindings, ...risk.dependencyFindings, ...risk.reviewRequirements] : [];
}

export function vulnerabilityForFinding(result: SecurityReviewResponse, finding: RiskFinding): Vulnerability | undefined {
  // Prefer persisted identity. A legacy fallback must identify exactly one location.
  if (finding.vulnerabilityId != null) return result.vulnerabilities.find(v => v.vulnerabilityId === finding.vulnerabilityId);
  const matches = result.vulnerabilities.filter(v => v.ruleId === finding.ruleId && finding.sourceFiles.includes(v.filePath));
  return matches.length === 1 ? matches[0] : undefined;
}

export function findingTitle(result: SecurityReviewResponse, finding: RiskFinding): string {
  if (finding.source === 'DEPENDENCY') return `${finding.packageName ?? '라이브러리'} ${finding.version ?? ''} 업데이트 검토`;
  if (finding.source === 'ANALYSIS') return finding.packageName
    ? `${finding.packageName}의 실제 사용 버전 확인` : '배포 판단에 필요한 분석 정보 확인';
  const vulnerability = vulnerabilityForFinding(result, finding);
  return vulnerability ? codeExplanation(vulnerability).title : '코드에서 발견된 문제 확인';
}

export function codeExplanation(v: Vulnerability): { title: string; location?: string } {
  switch (v.ruleId) {
    case 'HARDCODED_SECRET':
    case 'HARDCODED_FRONTEND_SECRET':
    case 'HARDCODED_PASSWORD': return { title: '비밀번호나 API Key가 코드에 직접 들어 있을 수 있습니다.' };
    case 'DOCKER_SECRET_ENV': return { title: '비밀번호나 API Key처럼 보호해야 할 값이 파일에 직접 들어가 있을 가능성이 있습니다.', location: 'Dockerfile의 ENV 설정' };
    case 'K8S_SECRET_PLAIN_TEXT': return { title: '보호해야 할 비밀 값이 그대로 저장되어 있을 가능성이 있습니다.', location: 'Kubernetes Secret 설정 파일' };
    case 'DOCKER_ROOT_USER': return { title: '컨테이너가 너무 높은 권한으로 실행될 수 있습니다.', location: 'Dockerfile의 USER 설정' };
    default: return { title: v.message };
  }
}

export function semanticStatusText(snapshot?: SemanticSnapshot | null, mode?: SecurityReviewResponse['scanMode']): string {
  if (!snapshot) return mode === 'AI_ENHANCED'
    ? 'AI 강화 분석의 실행 기록이 없습니다. 추가 코드 검토 여부를 확인할 수 없습니다.'
    : '이 분석에는 추가 코드 검토 기록이 없습니다.';
  if (snapshot.scanMode === 'AI_ENHANCED' && snapshot.semanticReviewStatus === 'NOT_REQUESTED')
    return 'AI 강화 분석을 선택했지만 현재 외부 AI 분석이 비활성화되어 추가 코드 검토는 실행되지 않았습니다.';
  switch (snapshot.semanticReviewStatus) {
    case 'NOT_REQUESTED': return '기본 분석으로 진행하여 AI 추가 코드 검토는 실행하지 않았습니다.';
    case 'UNAVAILABLE': return 'AI 추가 코드 검토를 실행할 수 없었습니다. 분석 설정 또는 코드 수집 상태 확인이 필요합니다.';
    case 'NO_SUPPORTED_CONTEXT': return 'AI가 검토할 수 있는 코드 영역을 찾지 못해 추가 검토를 실행하지 않았습니다.';
    case 'FAILED': return 'AI 추가 코드 검토에 실패했습니다. 확인을 완료한 상태가 아닙니다.';
    case 'REJECTED': return 'AI 응답의 근거를 확인하지 못해 후보를 표시하지 않았습니다.';
    case 'PARTIAL': return '일부 AI 후보의 근거를 확인하지 못했습니다. 확인된 후보만 표시합니다.';
    case 'COMPLETED': return '선택된 코드 영역의 AI 추가 검토를 완료했습니다.';
  }
}

export function reviewCounts(result: SecurityReviewResponse) {
  const summary = result.riskAssessment?.prioritySummary;
  // Display server priorities and independent AI candidates, never recalculate risk.
  return {
    blocking: summary?.BLOCKING ?? null,
    review: summary?.REVIEW_REQUIRED ?? null,
    recommended: summary?.SHOULD_FIX ?? null,
    candidates: result.semanticReview?.candidates.length ?? 0,
  };
}
