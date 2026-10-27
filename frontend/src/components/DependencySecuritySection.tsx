import type { RiskAssessment, ScaResult, RemediationSnapshot } from '../types/securityReview';
import { DependencyFindingCard } from './DependencyFindingCard';
import { IncompleteDependencyCard } from './IncompleteDependencyCard';
import { dependencyText } from './dependencyGuidance';
import { DependencyActionGroups } from './DependencyContextDetails';
import { securityTerms, inspectionLabel } from './uiLanguage';

export function ScaAssessmentNotice({ sca }: { sca?: ScaResult | null; riskAssessment?: RiskAssessment | null }) {
  if (sca?.status === 'COMPLETE') return null;
  return <p className="review-caution">라이브러리 보안 확인이 완료되지 않았습니다. 미조회·미해결 항목의 안전 여부는 확인되지 않았습니다.</p>;
}

export function DependencySecuritySection({ sca, riskAssessment, remediation, reviewId }: {
  sca?: ScaResult | null; riskAssessment?: RiskAssessment | null; remediation?: RemediationSnapshot | null;
  reviewId?: number | null;
}) {
  if (!sca) return <section className="sca-section" aria-label="사용 중인 라이브러리 문제">
    <h2>{securityTerms.libraries}</h2><p>이 이력에는 외부 라이브러리 검사 결과가 없습니다. 다시 검사해 주세요.</p>
  </section>;
  const canonical = riskAssessment && riskAssessment.schemaVersion >= 2
    ? riskAssessment.dependencyFindings.flatMap(finding => finding.dependency ? [finding.dependency] : [])
    : sca.dependencyVulnerabilities;
  const unresolved = sca.components.filter(component => component.versionResolution !== 'EXACT');
  return <section className="sca-section" aria-label="사용 중인 라이브러리 문제">
    <div className="section-heading"><h2>{securityTerms.libraries}</h2><span>{inspectionLabel(sca.status)}</span></div>
    <p className="section-lead">{sca.status==='COMPLETE'?'프로젝트에 포함된 외부 코드 중 알려진 보안 문제가 있는 항목을 확인했어요.':'프로젝트에 포함된 외부 코드의 보안 정보예요. 확인하지 못한 항목은 아래 검사 상태를 참고해 주세요.'}</p>
    <ScaAssessmentNotice sca={sca} />
    {(sca.components.some(c => c.ecosystem === 'PYPI') || sca.manifests?.some(m => /(?:requirements|pyproject|poetry|pipfile|uv\.lock|pylock)/i.test(m.filePath))) &&
      <p className="review-caution">이 화면은 Python 라이브러리의 선언과 알려진 보안 정보를 보여줘요. 실제 설치·간접 의존성 전체는 미확인이고, Python 서버 코드의 인증·권한·데이터 흐름 결과와는 별개예요.</p>}
    <p>기존 규칙 기반 점수에는 미반영됩니다. 배포 판단에는 별도 위험 평가가 사용됩니다.</p>
    <p className="section-footnote">라이브러리 분석 시각: <time dateTime={sca.analyzedAt}>{sca.analyzedAt ? new Date(sca.analyzedAt).toLocaleString('ko-KR') : '미기록'}</time>. 공지별 갱신 시점과 다르며, 현재 운영 환경을 조회한 시각이 아닙니다.</p>
    <dl className="sca-metrics">
      <div><dt>발견한 패키지·버전 조합</dt><dd>{sca.summary.dependenciesDiscovered}</dd></div>
      <div><dt>조회 완료 패키지·버전 조합</dt><dd>{sca.summary.dependenciesAnalyzed}</dd></div>
      <div><dt>보안 공지가 있는 패키지·버전 조합</dt><dd>{sca.summary.vulnerableDependencies}</dd></div>
      <div><dt>표시된 보안 공지·패키지·버전 항목</dt><dd>{canonical.length}</dd></div>
      <div><dt>버전 확인 필요 조합</dt><dd>{sca.summary.unresolvedDependencies}</dd></div>
    </dl>
    <p className="section-footnote">같은 패키지에 여러 보안 공지가 연결될 수 있어요. 공지 항목 수는 고유 취약점 수나 수정 작업 수와 달라요.</p>
    <details><summary>보안 공지 ID와 항목 수의 차이</summary><p>패키지·버전 조합은 생태계별로 구분합니다. 원본 조회의 공지 항목은 {sca.summary.dependencyVulnerabilities}개이며, 같은 공지를 통합하면 표시 수와 다를 수 있습니다. 전체 고유 보안 공지 ID 수는 API에서 별도 집계하지 않으며, 표시 항목 수를 고유 ID 수로 해석하지 않습니다. 각 항목의 ID·별칭·영향 버전은 상세 근거에서 확인하세요.</p></details>
    {canonical.length === 0 && <p>{sca.status === 'COMPLETE'
      ? '조회한 정확한 버전에서 알려진 취약점이 반환되지 않았습니다. 프로젝트 전체의 안전을 보장하지 않습니다.'
      : '표시할 라이브러리 문제가 없습니다. 미조회 항목과 분석 상태를 확인해 주세요.'}</p>}
    <DependencyActionGroups sca={sca} />
    <div className="vulnerability-list">{canonical.map(dep => <DependencyFindingCard components={sca.components}
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
