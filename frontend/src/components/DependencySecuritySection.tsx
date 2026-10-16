import type { RiskAssessment, ScaResult, RemediationSnapshot } from '../types/securityReview';
import { DependencyFindingCard } from './DependencyFindingCard';
import { IncompleteDependencyCard } from './IncompleteDependencyCard';
import { dependencyText } from './dependencyGuidance';

const statusLabels: Record<ScaResult['status'], string> = {
  COMPLETE: '조회 완료', PARTIAL: '일부만 확인됨', UNAVAILABLE: '조회하지 못함',
  NO_MANIFEST: '지원하는 의존성 파일 없음', DISABLED: '라이브러리 검사 비활성',
};

export function ScaAssessmentNotice({ sca }: { sca?: ScaResult | null; riskAssessment?: RiskAssessment | null }) {
  if (sca?.status === 'COMPLETE') return null;
  return <p className="review-caution">라이브러리 보안 확인이 완료되지 않았습니다. 미조회·미해결 항목의 안전 여부는 확인되지 않았습니다.</p>;
}

export function DependencySecuritySection({ sca, riskAssessment, remediation, reviewId }: {
  sca?: ScaResult | null; riskAssessment?: RiskAssessment | null; remediation?: RemediationSnapshot | null;
  reviewId?: number | null;
}) {
  if (!sca) return <section className="sca-section" aria-label="사용 중인 라이브러리 문제">
    <h2>사용 중인 라이브러리 문제</h2><p>이 분석 이력에는 라이브러리 검사 결과가 없습니다. 재분석이 필요합니다.</p>
  </section>;
  const canonical = riskAssessment && riskAssessment.schemaVersion >= 2
    ? riskAssessment.dependencyFindings.flatMap(finding => finding.dependency ? [finding.dependency] : [])
    : sca.dependencyVulnerabilities;
  const unresolved = sca.components.filter(component => component.versionResolution !== 'EXACT');
  return <section className="sca-section" aria-label="사용 중인 라이브러리 문제">
    <div className="section-heading"><h2>사용 중인 라이브러리 문제</h2><span>{statusLabels[sca.status]}</span></div>
    <ScaAssessmentNotice sca={sca} />
    <p>기존 규칙 기반 점수에는 미반영됩니다. 배포 판단에는 별도 위험 평가가 사용됩니다.</p>
    <dl className="sca-metrics">
      <div><dt>발견한 패키지·버전</dt><dd>{sca.summary.dependenciesDiscovered}</dd></div>
      <div><dt>조회 완료</dt><dd>{sca.summary.dependenciesAnalyzed}</dd></div>
      <div><dt>보안 문제</dt><dd>{canonical.length}</dd></div>
      <div><dt>버전 확인 필요</dt><dd>{sca.summary.unresolvedDependencies}</dd></div>
    </dl>
    {canonical.length === 0 && <p>{sca.status === 'COMPLETE'
      ? '조회한 정확한 버전에서 알려진 취약점이 반환되지 않았습니다. 프로젝트 전체의 안전을 보장하지 않습니다.'
      : '표시할 라이브러리 문제가 없습니다. 미조회 항목과 분석 상태를 확인해 주세요.'}</p>}
    <div className="vulnerability-list">{canonical.map(dep => <DependencyFindingCard
      key={[dep.ecosystem, dep.packageName, dep.installedVersion, dep.osvId].join('|')} dependency={dep}
      remediation={remediation} intelligence={riskAssessment?.threatIntelligence}
      finding={riskAssessment?.dependencyFindings.find(finding => finding.ecosystem === dep.ecosystem &&
        finding.packageName === dep.packageName && finding.version === dep.installedVersion && finding.advisoryId === dep.osvId)}
    />)}</div>
    {unresolved.length > 0 && <details><summary>버전 확인이 필요한 라이브러리 ({unresolved.length}개 위치)</summary>
      <div className="vulnerability-list">{unresolved.map((component, index) => {
        const finding = riskAssessment?.reviewRequirements.find(f => f.reasonCode === 'UNRESOLVED_VERSION'
          && f.ecosystem === component.ecosystem && f.packageName === component.packageName && f.version === component.version);
        return <IncompleteDependencyCard key={`${reviewId}:${index}`} reviewId={finding ? reviewId : null} finding={finding ?? {
          findingId: `component:${index}`, source: 'DEPENDENCY', findingCategory: 'DEPENDENCY',
          vulnerabilityId: null, ruleId: null, ecosystem: component.ecosystem, packageName: component.packageName,
          version: component.version, advisoryId: null, sourceFiles: [component.sourceFile],
          priority: 'REVIEW_REQUIRED', reasonCode: 'UNRESOLVED_VERSION', priorityReason: '현재 정적 분석 범위에서 이름 또는 정확한 버전을 확인하지 못했습니다.', dependencyFacts: null,
        }} />;
      })}</div>
    </details>}
    {!!sca.warnings.length && <details><summary>조회 중 확인하지 못한 정보</summary>
      <ul>{sca.warnings.map((warning, index) => <li key={index}>{dependencyText(warning)}</li>)}</ul>
    </details>}
  </section>;
}
