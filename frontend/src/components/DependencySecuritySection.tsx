import type { RiskAssessment, ScaResult } from '../types/securityReview';
import { FindingPriority } from './RiskAssessmentSection';

const statusLabels: Record<ScaResult['status'], string> = {
  COMPLETE: '조회 완료',
  PARTIAL: '일부 분석 완료',
  UNAVAILABLE: '조회 불가',
  NO_MANIFEST: '지원 manifest 없음',
  DISABLED: 'SCA 비활성',
};
const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

export function ScaAssessmentNotice({ sca, riskAssessment }: { sca?: ScaResult | null; riskAssessment?: RiskAssessment | null }) {
  const incomplete = !sca || sca.status !== 'COMPLETE';
  const count = riskAssessment && riskAssessment.schemaVersion >= 2
    ? riskAssessment.dependencyFindings.length : sca?.summary.dependencyVulnerabilities ?? 0;
  if (!incomplete && count === 0) return null;
  return <div className="feedback-message sca-assessment-notice" role="status">
    <strong>{incomplete ? '의존성 보안 확인 미완료' : '의존성 취약점 ' + count + '건 확인'}</strong>
    <p>{incomplete ? '미조회·미해결 의존성의 안전 여부는 확인되지 않았습니다. ' : ''}
      참고 점수와 기존 판정은 규칙 기반 결과입니다. 배포 여부는 상단의 위험 기반 배포 평가를 우선 확인하세요.</p>
  </div>;
}

export function DependencySecuritySection({ sca, riskAssessment }: { sca?: ScaResult | null; riskAssessment?: RiskAssessment | null }) {
  if (!sca) {
    return <section className="sca-section" aria-label="Dependency Security">
      <h2>Dependency Security</h2>
      <p>이 분석 이력에는 SCA 결과가 없습니다. 재분석하면 의존성을 확인할 수 있습니다.</p>
    </section>;
  }
  const canonicalFindings = riskAssessment && riskAssessment.schemaVersion >= 2
    ? riskAssessment.dependencyFindings.flatMap(finding => finding.dependency ? [finding.dependency] : [])
    : sca.dependencyVulnerabilities;
  const findings = [...canonicalFindings].sort(
    (a, b) => order[a.severity ?? 'UNKNOWN'] - order[b.severity ?? 'UNKNOWN'],
  );
  const unresolved = sca.components.filter((component) => component.versionResolution !== 'EXACT');
  return (
    <section className="sca-section" aria-label="Dependency Security">
      <div className="section-heading">
        <h2>Dependency Security</h2>
        <span className="sca-status">{statusLabels[sca.status]}</span>
      </div>
      <p>OSV 조회 결과 · 기존 규칙 기반 점수에는 미반영 · 별도 위험 기반 배포 평가에 사용</p>
      <dl className="sca-metrics">
        <div><dt>발견 패키지/버전</dt><dd>{sca.summary.dependenciesDiscovered}</dd></div>
        <div><dt>조회 완료</dt><dd>{sca.summary.dependenciesAnalyzed}</dd></div>
        <div><dt>취약 패키지/버전</dt><dd>{sca.summary.vulnerableDependencies}</dd></div>
        <div><dt>의존성 취약점 (중복 통합)</dt><dd>{findings.length}</dd></div>
        <div><dt>버전 미해결</dt><dd>{sca.summary.unresolvedDependencies}</dd></div>
      </dl>
      <div className="sca-severities" aria-label="의존성 심각도 분포">
        {Object.keys(order).map(severity => (
          <span key={severity}>{severity === 'UNKNOWN' ? '심각도 미확인' : severity}: {findings.filter(finding => (finding.severity ?? 'UNKNOWN') === severity).length}</span>
        ))}
      </div>
      {sca.warnings.length > 0 && <ul className="sca-warnings">
        {sca.warnings.map((warning, index) => <li key={index}>{warning}</li>)}
      </ul>}
      {findings.length === 0 && <p className="sca-empty">
        {sca.status === 'COMPLETE'
          ? '조회한 정확한 버전에서 알려진 취약점이 반환되지 않았습니다.'
          : '현재 표시할 의존성 취약점이 없습니다. 미조회 항목과 분석 상태를 확인해 주세요.'}
      </p>}
      <div className="vulnerability-list">
        {findings.map((finding) => (
          <article className="vulnerability-item" key={[finding.ecosystem, finding.packageName, finding.installedVersion, finding.osvId].join('|')}>
            <div className="vulnerability-header">
              <div>
                <span className="rule-id">DEPENDENCY · {finding.ecosystem}</span>
                <h3>{finding.packageName}</h3>
              </div>
              <span className={finding.severity ? 'severity severity-' + finding.severity.toLowerCase() : 'severity'}>
                {finding.severity ?? '미확인'}
              </span>
            </div>
            <FindingPriority finding={riskAssessment?.dependencyFindings.find(risk =>
              risk.ecosystem === finding.ecosystem && risk.packageName === finding.packageName &&
              risk.version === finding.installedVersion && risk.advisoryId === finding.osvId)} />
            <dl className="sca-finding-details">
              <div><dt>Installed Version</dt><dd>{finding.installedVersion}</dd></div>
              <div><dt>Vulnerability ID</dt><dd>{finding.osvId}</dd></div>
              <div><dt>Aliases</dt><dd>{finding.aliases.join(', ') || '없음'}</dd></div>
              <div><dt title="OSV에 기록된 계열별 수정 버전입니다. 현재 프로젝트와의 호환성을 확인하세요.">Fixed Versions</dt>
                <dd>{finding.fixedVersions.join(', ') || '확인되지 않음'}</dd></div>
              {finding.cvssScore !== null && <div><dt>CVSS</dt><dd>{finding.cvssScore}</dd></div>}
              <div><dt>Source Files</dt><dd>{finding.sourceFiles.join(', ')}</dd></div>
            </dl>
            <p>{finding.summary || '상세 설명을 확인하지 못했습니다.'}</p>
            {finding.referenceUrls.filter((url) => /^https?:\/\//i.test(url)).slice(0, 3).map((url) => (
              <p key={url}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a></p>
            ))}
          </article>
        ))}
      </div>
      {unresolved.length > 0 && <details className="sca-unresolved">
        <summary>버전 확인이 필요한 의존성 ({unresolved.length}개 위치)</summary>
        <ul>{unresolved.map((component, index) => <li key={index}>
          <strong>{component.packageName}</strong> · {component.version ?? '버전 없음'} · {component.versionResolution}
          <br /><span>{component.sourceFile}</span>
        </li>)}</ul>
      </details>}
    </section>
  );
}
