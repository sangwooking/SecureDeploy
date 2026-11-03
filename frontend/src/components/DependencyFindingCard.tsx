import {useEffect,useState} from 'react';
import {AdvisoryMetadataRefresh} from './AdvisoryMetadataRefresh';
import {currentSeriesFix,versionBasis} from './dependencyVersion';
import { EvidenceSupportLayout } from './EvidenceSupportLayout';
import type { ReactNode } from 'react';
import type { DependencyComponent, DependencyVulnerability, RemediationSnapshot, RiskFinding, ThreatIntelligenceSnapshot } from '../types/securityReview';
import { DependencyContextDetails, dependencyLocations } from './DependencyContextDetails';
import { FindingRemediation } from './FindingRemediation';
import { ThreatIntelligenceDetails } from './ThreatIntelligenceDetails';
import { priorityLabels } from './reviewPresentation';
import { dependencyText, knownDependencyValue, unconfirmed } from './dependencyGuidance';
import { DependencyRepairSummary } from './DependencyRepairSummary';

export function DependencyFindingCard({ dependency: original, reviewId, finding, remediation, intelligence, components, support, embedded = false }: {
  reviewId?:number|null;dependency: DependencyVulnerability; finding?: RiskFinding;
  remediation?: RemediationSnapshot | null; intelligence?: ThreatIntelligenceSnapshot | null;
  components?: DependencyComponent[]; support?: ReactNode; embedded?: boolean;
}) {
  const [supplement,setSupplement]=useState<{original:DependencyVulnerability;reviewId?:number|null;value:DependencyVulnerability}|null>(null);
  useEffect(()=>setSupplement(null),[reviewId,original]);
  const dep=supplement?.original===original&&supplement.reviewId===reviewId?supplement.value:original;
  const fixed=currentSeriesFix(dep);
  const npmPackage = dep.ecosystem==='NPM' && /^(?:@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/.test(dep.packageName)
    ? `https://www.npmjs.com/package/${dep.packageName.split('/').map(encodeURIComponent).join('/')}` : null;
  const advisory = /^(?:CVE-|GHSA-|OSV-|PYSEC-|GO-|RUSTSEC-)[a-z0-9-]+$/i.test(dep.osvId)
    ? `https://osv.dev/vulnerability/${encodeURIComponent(dep.osvId)}` : null;
  const knownExploited = [dep.osvId, ...dep.aliases].some(id => intelligence?.cves[id.toUpperCase()]?.kev.knownExploited === true);
  const evidence=<><span className="source-label">SCA 보안 공지 · 실제 영향은 추가 확인</span>
    <span className={`risk-badge risk-${finding?.priority?.toLowerCase() ?? 'review_required'}`}>
      {finding ? priorityLabels[finding.priority]??'우선순위 미기록' : '우선순위 미평가'}
    </span>
    <h3>{dependencyText(dep.packageName)} 업데이트 검토</h3>
    <p>{dep.ecosystem === 'PYPI' ? '정적 선언에서 확인한' : '사용 중인'} {dependencyText(dep.installedVersion)} 버전에 알려진 보안 문제가 보고되어 있습니다. 실제 영향은 사용 방식과 버전에 따라 달라집니다.</p>
    {dep.ecosystem === 'PYPI' && <p className="review-caution">실제 설치 여부는 미확인입니다. 이 라이브러리 조회가 Python 서버 코드의 인증·권한 및 데이터 흐름을 검증하는 것은 아니에요. 서버 코드 검사 결과는 별도로 확인해 주세요.</p>}
    {knownExploited && <p className="review-caution">분석 당시 정보에 실제 공격에서 악용된 이력이 있습니다. 이 프로젝트가 공격받았다는 뜻은 아닙니다.</p>}
    <p className="advisory-identity"><strong>보안 공지</strong> <code>{dep.osvId}</code></p>
    {(npmPackage||advisory)&&<p>
      {advisory&&<a href={advisory} target="_blank" rel="noopener noreferrer">OSV 공지 원문</a>}
      {npmPackage&&<> · <a href={npmPackage} target="_blank" rel="noopener noreferrer">공식 npm 패키지</a></>}
    </p>}
    <dl className="dependency-versions">
      <div><dt>라이브러리</dt><dd>{dependencyText(dep.packageName)}</dd></div>
      <div><dt>현재 버전</dt><dd>{dependencyText(dep.installedVersion)}</dd></div>
      <div><dt>공지의 수정 버전 근거</dt><dd><strong>{fixed??'현재 계열의 수정 경계 미확인'}</strong><p>공식 공지의 수정 경계 · 적용 가능성/호환성 미확인</p><details><summary>모든 수정 버전 근거</summary>{dep.fixedVersions.map(knownDependencyValue).filter(Boolean).join(', ') || unconfirmed}</details></dd></div>
      <div><dt>{dep.ecosystem === 'PYPI' ? '의존성 선언·연결 위치' : '버전을 확인한 파일'}</dt><dd className="finding-location">{dependencyText(dep.sourceFiles.join(', '))}</dd></div>
    </dl>
    <DependencyRepairSummary dependency={dep} components={components}/>
    {original.fixedVersions.length===0&&<AdvisoryMetadataRefresh reviewId={reviewId} finding={finding} dependency={original} onMetadata={value=>setSupplement({original,reviewId,value})}/>}
    <p>{versionBasis(dep.sourceFiles)}</p><details><summary>상위 의존성과 선언 위치</summary><DependencyContextDetails locations={dependencyLocations(dep, components)} /></details>
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
    <details><summary>저장된 AI 설명</summary><FindingRemediation finding={finding} snapshot={remediation} /></details>
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
      {!!dep.affectedRanges?.length && <details><summary>OSV 버전 범위 근거</summary>
        <p>각 범위의 시작·수정 경계를 보존한 정보입니다. 서로 다른 계열의 수정 버전을 하나의 안전한 최소 버전으로 합치지 않습니다.</p>
        {dep.affectedRanges.map((range, i) => <div key={i}><strong>{range.type}</strong>
          <ul>{range.events.map((e, j) => <li key={j}>{[
            e.introduced && `영향 시작: ${e.introduced}`, e.fixed && `수정: ${e.fixed}`,
            e.lastAffected && `마지막 영향: ${e.lastAffected}`, e.limit && `범위 상한: ${e.limit}`,
          ].filter(Boolean).join(' · ')}</li>)}</ul>
        </div>)}
      </details>}
      <ThreatIntelligenceDetails finding={dep} snapshot={intelligence} />
      {dep.referenceUrls.filter(url => /^https?:\/\//i.test(url)).slice(0, 3).map(url =>
        <p key={url}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a></p>)}
    </details>
  </>;
  return embedded ? <article className="dependency-finding">{evidence}</article> : <article className="vulnerability-item action-finding dependency-finding"><EvidenceSupportLayout evidence={evidence} support={support??<><p className="source-label">근거 기반 안내 · AI 의견 미연결</p><h4>어떻게 수정하나요?</h4><p>현재 계열에 맞는 공지 수정 버전을 검토하고, 상위 의존성 제약과 호환성을 확인하세요.</p><p>패키지 관리자로 잠금 파일을 재생성한 뒤 Diff·사용자 승인·재검사를 진행하세요. 표시된 수정 버전은 AI 추천이나 전체 안전 보장이 아닙니다.</p><FindingRemediation finding={finding} snapshot={remediation} /></>} /></article>;
}
