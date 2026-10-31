import type { DependencyComponent, DependencyVulnerability } from '../types/securityReview';
import { dependencyText } from './dependencyGuidance';

/** Saved lockfile observations only. Never treats registry/latest or a direct update as remediation. */
export function dependencyRepairEvidence(dep: DependencyVulnerability, components: DependencyComponent[] = []) {
  const matching = components.filter(c => c.ecosystem === dep.ecosystem && c.packageName === dep.packageName && c.version === dep.installedVersion);
  const paths = [...new Set(matching.map(c => c.context?.installedPath).filter((p): p is string => !!p))];
  const parents = [...new Set(matching.flatMap(c => c.context?.paths ?? []).flatMap(p => {
    const parent = p.chain[p.chain.length - 2];
    return parent ? [`${parent.packageName}@${parent.version ?? '버전 미확인'}`] : [];
  }))];
  const chains = [...new Set(matching.flatMap(c => c.context?.paths ?? []).map(p => p.chain.map(h => `${h.packageName}@${h.version ?? '미확인'}`).join(' → ')).filter(Boolean))];
  const otherDirect = components.some(c => c.ecosystem === dep.ecosystem && c.packageName === dep.packageName && c.direct === true && c.version !== dep.installedVersion);
  return { paths, parents, chains, otherDirect, indirect: matching.some(c => c.direct === false), complete: matching.length > 0 && matching.every(c => c.context?.pathsComplete === true) };
}

export function DependencyRepairSummary({ dependency, components }: { dependency: DependencyVulnerability; components?: DependencyComponent[] }) {
  if (dependency.ecosystem !== 'NPM') return null;
  const evidence = dependencyRepairEvidence(dependency, components);
  return <section aria-label="잠금 의존성 수정 상태" className="dependency-repair-summary">
    <h4>업데이트 전 확인</h4>
    <p>{evidence.parents.length ? `${evidence.parents.map(dependencyText).join(', ')}가 이 버전을 함께 설치합니다.` : evidence.indirect ? '함께 설치되는 의존성입니다. 상위 패키지는 아직 확인하지 못했습니다.' : '직접 선언과 잠금 경로를 확인하세요.'}</p>
    {!!evidence.chains.length && <p>설치 선언 경로: {evidence.chains.slice(0, 3).map(dependencyText).join(' / ')}{evidence.chains.length > 3 ? ' · 추가 경로는 상세에서 확인' : ''}</p>}
    {evidence.otherDirect && evidence.indirect && <p className="review-caution">직접 선언의 다른 버전과 별개로, 보안 공지에 해당하는 중첩 버전이 남아 있습니다.</p>}
    <p>수정 가능 여부: {evidence.indirect ? '상위 패키지 업데이트부터 검토' : '직접 선언 업데이트 검토'} · 호환성 미확인</p>
    <p>남은 잠금 경로: {evidence.paths.length ? `${evidence.paths.length}곳에서 현재 버전 확인` : '기록 부족'}{!evidence.complete ? ' · 전체 경로 확인 필요' : ''}</p>
    <p>표시된 수정 버전은 공지의 근거입니다. 모든 영향받는 잠금 경로를 갱신하고 재검사하기 전에는 해결로 판정하지 않습니다. 공지 매칭 건수는 독립적인 취약점 수와 다릅니다.</p>
  </section>;
}
