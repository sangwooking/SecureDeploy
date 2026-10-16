import type { DependencyComponent, DependencyVulnerability, RemediationSnapshot, RiskFinding, ThreatIntelligenceSnapshot } from '../types/securityReview';
import { DependencyContextDetails, dependencyLocations } from './DependencyContextDetails';
import { FindingRemediation } from './FindingRemediation';
import { ThreatIntelligenceDetails } from './ThreatIntelligenceDetails';
import { priorityLabels } from './reviewPresentation';
import { dependencyText, knownDependencyValue, unconfirmed } from './dependencyGuidance';

export function DependencyFindingCard({ dependency: dep, finding, remediation, intelligence, components }: {
  dependency: DependencyVulnerability; finding?: RiskFinding;
  remediation?: RemediationSnapshot | null; intelligence?: ThreatIntelligenceSnapshot | null;
  components?: DependencyComponent[];
}) {
  const knownExploited = [dep.osvId, ...dep.aliases].some(id => intelligence?.cves[id.toUpperCase()]?.kev.knownExploited === true);
  return <article className="vulnerability-item action-finding dependency-finding">
    <span className={`risk-badge risk-${finding?.priority.toLowerCase() ?? 'review_required'}`}>
      {finding ? priorityLabels[finding.priority] : '우선순위 미평가'}
    </span>
    <h3>{dependencyText(dep.packageName)} 업데이트 검토</h3>
    <p>사용 중인 {dependencyText(dep.installedVersion)} 버전에 알려진 보안 문제가 보고되어 있습니다. 실제 영향은 사용 방식과 버전에 따라 달라집니다.</p>
    {knownExploited && <p className="review-caution">분석 당시 정보에 실제 공격에서 악용된 이력이 있습니다. 이 프로젝트가 공격받았다는 뜻은 아닙니다.</p>}
    <dl className="dependency-versions">
      <div><dt>라이브러리</dt><dd>{dependencyText(dep.packageName)}</dd></div>
      <div><dt>현재 버전</dt><dd>{dependencyText(dep.installedVersion)}</dd></div>
      <div><dt>수정이 확인된 버전</dt><dd>{dep.fixedVersions.map(knownDependencyValue).filter(Boolean).join(', ') || unconfirmed}</dd></div>
      <div><dt>버전을 확인한 파일</dt><dd className="finding-location">{dependencyText(dep.sourceFiles.join(', '))}</dd></div>
    </dl>
    <DependencyContextDetails locations={dependencyLocations(dep, components)} />
    <details className="action-details"><summary>업데이트 방법 보기</summary>
      <h4>내가 해야 할 일</h4>
      <ol>
        <li>위 확인 위치와 의존성 경로를 대조하세요. 간접 의존성이라면 상위 패키지의 manifest 선언을 먼저 검토하고, lockfile만 직접 편집하지 마세요.</li>
        <li>{dep.fixedVersions.length > 0
          ? '알려진 수정 버전 중 현재 사용 계열에 맞는 버전과 호환성을 확인하여 업데이트하세요.'
          : '현재는 수정 버전을 확인하지 못했습니다. 공식 보안 공지에서 적용 가능한 조치와 버전을 확인하세요.'}</li>
        <li>의존성 및 잠금 파일을 갱신하고 빌드와 관련 기능 테스트를 실행하세요.</li>
        <li>SecureDeploy로 다시 검사하여 문제가 남아 있는지 확인하세요.</li>
      </ol>
      <p>표시된 수정 버전은 해당 보안 문제에 대한 정보이며, 모든 취약점 해결이나 프로젝트 호환성을 보장하지 않습니다.</p>
      <h4>알려진 보안 문제</h4><p>{dependencyText(dep.summary)}</p>
      {finding && <p>{finding.priorityReason}</p>}
    </details>
    <FindingRemediation finding={finding} snapshot={remediation} />
    <details className="technical-details"><summary>기술 정보 보기</summary>
      <p className="finding-location"><strong>위치</strong> <code>{dep.sourceFiles.join(', ') || '저장된 위치 없음'}</code></p>
      <dl className="technical-grid">
        <div><dt>Ecosystem</dt><dd>{dep.ecosystem}</dd></div>
        <div><dt>OSV / Advisory</dt><dd>{dep.osvId}</dd></div>
        <div><dt>CVE / Aliases</dt><dd>{dep.aliases.join(', ') || '없음'}</dd></div>
        <div><dt>Severity / CVSS</dt><dd>{dep.severity ?? '미확인'} / {dep.cvssScore ?? '미확인'}</dd></div>
        {finding && <div><dt>Priority / Reason code</dt><dd>{finding.priority} / {finding.reasonCode}</dd></div>}
      </dl>
      {finding && <p>{finding.priorityReason}</p>}
      <ThreatIntelligenceDetails finding={dep} snapshot={intelligence} />
      {dep.referenceUrls.filter(url => /^https?:\/\//i.test(url)).slice(0, 3).map(url =>
        <p key={url}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a></p>)}
    </details>
  </article>;
}
