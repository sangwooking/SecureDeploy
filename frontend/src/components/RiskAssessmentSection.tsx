import type { RiskAssessment, RiskFinding, RiskPriority } from '../types/securityReview';

const priorityLabels: Record<RiskPriority, string> = {
  BLOCKING: '배포 전 필수 조치', SHOULD_FIX: '수정 권장',
  REVIEW_REQUIRED: '추가 검토 필요', INFORMATIONAL: '개선·참고',
};
const priorities: RiskPriority[] = ['BLOCKING', 'SHOULD_FIX', 'REVIEW_REQUIRED', 'INFORMATIONAL'];

export function FindingPriority({ finding }: { finding?: RiskFinding }) {
  if (!finding) return <p className="risk-unavailable">우선순위 평가 없음</p>;
  return <div className="finding-priority">
    <span className={'risk-badge risk-' + finding.priority.toLowerCase()}>
      {finding.priority} · {priorityLabels[finding.priority]}
    </span>
    <p>{finding.priorityReason}</p>
  </div>;
}

export function RiskAssessmentSection({ assessment }: { assessment?: RiskAssessment | null }) {
  if (!assessment) return <section className="risk-assessment" aria-label="위험 기반 배포 평가">
    <h2>위험 기반 배포 평가</h2>
    <p>이 분석에는 위험 우선순위 평가가 없습니다. 재분석이 필요합니다.</p>
    <p>기존 점수만으로 배포 가능 여부를 판단하지 않습니다.</p>
  </section>;
  const status = assessment.prioritizedDeploymentAssessment;
  return <section className={'risk-assessment assessment-' + status.toLowerCase()} aria-label="위험 기반 배포 평가">
    <div className="section-heading"><h2>위험 기반 배포 평가</h2><strong>{status}</strong></div>
    <p className="risk-primary-label">배포 판단의 기준 · Code + SCA{assessment.schemaVersion >= 3 ? ' + Threat Intelligence' : ''} + 분석 완성도</p>
    <p>{assessment.assessmentReason}</p>
    <dl className="sca-metrics risk-summary">
      {priorities.map(priority => <div key={priority}>
        <dt>{priorityLabels[priority]} · {priority}</dt><dd>{assessment.prioritySummary[priority]}</dd>
      </div>)}
    </dl>
    <details>
      <summary>분석 범위와 항목 구분 · {assessment.policyVersion}</summary>
      <p>Rule Engine: {assessment.assessmentCoverage.ruleEngine} · SCA: {assessment.assessmentCoverage.sca} · AI: {assessment.assessmentCoverage.ai}</p>
      <p>Threat Intelligence: {assessment.assessmentCoverage.threatIntelligence ?? '저장된 평가 없음'}</p>
      {assessment.threatPolicy && <p>HIGH 정확 버전 EPSS 승격 기준: score ≥ {assessment.threatPolicy.blockingScore}, percentile ≥ {assessment.threatPolicy.blockingPercentile}</p>}
      <p>{assessment.assessmentCoverage.scopeNote}</p>
      {(['CODE', 'DEPENDENCY', 'ANALYSIS'] as const).map(source => <p key={source}>
        {source}: {priorities.map(priority => `${priority} ${assessment.prioritySummaryBySource[source][priority]}`).join(' · ')}
      </p>)}
    </details>
    {!!assessment.threatIntelligence?.warnings.length && <ul className="sca-warnings">
      {assessment.threatIntelligence.warnings.map((warning, index) => <li key={index}>{warning}</li>)}
    </ul>}
    <p className="risk-snapshot-note">분석 당시 평가입니다. 수정 완료 표시만으로 변경되지 않으며, 재분석으로 확인해야 합니다. READY도 절대적 안전을 보장하지 않습니다.</p>
    {!!assessment.dependencyCorrelations?.length && <details className="risk-correlations">
      <summary>통합된 dependency 보조 근거 ({assessment.dependencyCorrelations.length}건 · Priority 별도 합산 없음)</summary>
      {assessment.dependencyCorrelations.map((item, index) => <div className="risk-requirement" key={`${item.vulnerabilityId}-${index}`}>
        <strong>{item.observation.packageName} {item.observation.version}</strong>
        <p>{item.reason}</p>
        <p>{item.ruleId} · {item.filePath}:{item.line}</p>
        <p>원본 #{item.vulnerabilityId} · {item.observation.advisoryId ?? '개별 CVE 미지정 후보'}</p>
      </div>)}
    </details>}
    {assessment.reviewRequirements.length > 0 && <details className="risk-requirements">
      <summary>분석 공백·버전 확인 항목 ({assessment.reviewRequirements.length})</summary>
      {assessment.reviewRequirements.map(finding => <div key={finding.findingId} className="risk-requirement">
        <strong>{finding.packageName ? `${finding.packageName} ${finding.version ?? ''}` : finding.findingId === 'coverage:threat-intelligence' ? 'Threat Intelligence 확인 범위' : 'SCA 분석 범위'}</strong>
        <FindingPriority finding={finding} />
        {finding.sourceFiles.length > 0 && <p>{finding.sourceFiles.join(', ')}</p>}
      </div>)}
    </details>}
  </section>;
}
