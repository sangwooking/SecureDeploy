import type { DependencyComponent, DependencyVulnerability, ScaResult } from '../types/securityReview';
import { dependencyText } from './dependencyGuidance';

const environmentLabels = { DEVELOPMENT: '개발·테스트 선언 경로', PRODUCTION: '운영 의존성 선언 경로', SHARED: '개발·운영 양쪽 선언 경로', UNKNOWN: '사용 환경 확인 불가' };
export function dependencyLocations(dep: DependencyVulnerability, components: DependencyComponent[] = []) {
  return components.filter(c => c.ecosystem === dep.ecosystem && c.packageName === dep.packageName && c.version === dep.installedVersion);
}
export function DependencyContextDetails({ locations }: { locations: DependencyComponent[] }) {
  const contexts = locations.filter(c => c.context);
  if (!contexts.length) return <p>이 이력에는 상위 의존성 경로가 없습니다. 직접/간접 경로와 실제 수정 위치를 추가로 확인해야 합니다.</p>;
  return <details className="action-details"><summary>의존성 경로와 수정 위치 확인</summary>
    <p>아래는 manifest·lockfile의 선언 근거입니다. 운영 실행 여부나 공격 가능성을 확인한 것은 아닙니다. 개발 도구도 CI·빌드·테스트 입력에 따라 위험할 수 있습니다.</p>
    {contexts.map((component, i) => {
      const context = component.context!;
      return <section className="dependency-context" key={`${component.sourceFile}:${context.installedPath}:${i}`}>
        <h4>{environmentLabels[context.environment] ?? environmentLabels.UNKNOWN} · {component.direct == null ? '직접/간접 미확인' : component.direct ? '직접 의존성' : '간접 의존성'}</h4>
        <p className="finding-location">버전 확인 위치: {component.sourceFile}{component.line > 0 ? `:${component.line}` : context.lockLine > 0 ? `:${context.lockLine}` : ''} · {context.installedPath || '설치 위치 미확인'}</p>
        {context.paths.map((path, index) => <div key={index}>
          <p className="finding-location">{path.chain.map(hop => `${hop.packageName}@${hop.version ?? '버전 미확정'}`).join(' → ')}</p>
          <p>{path.declarationConfirmed ? '수정 검토 위치' : '선언 확인 근거 (실제 수정 파일 미확인)'}: <code>{path.declarationFile}{path.declarationLine > 0 ? `:${path.declarationLine}` : ''}</code> · {path.declarationSection}</p>
          <p>상위 패키지: {dependencyText(path.declaredPackage)} ({dependencyText(path.declaredVersion)}){path.optional ? ' · 선택 설치 경로' : ''}{path.peer ? ' · peer 경로' : ''}</p>
        </div>)}
        {!context.pathsComplete && <p className="review-caution">모든 경로를 확인하지 못했습니다. 표시된 경로 외 사용처가 있을 수 있습니다.</p>}
        {context.limitations.map((note, index) => <p key={index}>{note}</p>)}
      </section>;
    })}
    <p>상위 패키지의 호환성을 확인해 선언을 수정하고 패키지 관리자로 lockfile을 갱신하세요. lockfile만 수동 편집하지 마세요. 상위 패키지의 권장 버전은 현재 확인하지 못했습니다.</p>
  </details>;
}

export function dependencyActionGroups(sca: ScaResult) {
  const groups = new Map<string, { label: string; file: string; packages: Set<string>; advisories: Set<string> }>();
  for (const dep of sca.dependencyVulnerabilities) {
    const paths = dependencyLocations(dep, sca.components).flatMap(c => c.context?.paths ?? []).filter(p => p.declarationConfirmed);
    const candidates = paths.length ? paths.map(p => ({ label: p.declaredPackage, file: p.declarationFile }))
      : [{ label: dep.packageName, file: '상위 선언 위치 미확인' }];
    for (const candidate of candidates) {
      const key = `${dep.ecosystem}|${candidate.file}|${candidate.label}`;
      const group = groups.get(key) ?? { ...candidate, packages: new Set<string>(), advisories: new Set<string>() };
      group.packages.add(`${dep.packageName}@${dep.installedVersion}`);
      group.advisories.add(dep.osvId);
      groups.set(key, group);
    }
  }
  return [...groups.values()];
}

export function DependencyActionGroups({ sca }: { sca?: ScaResult | null }) {
  if (!sca?.dependencyVulnerabilities.length) return null;
  const groups = dependencyActionGroups(sca);
  return <section className="dependency-actions" aria-label="라이브러리 수정 작업 후보">
    <h3>라이브러리 수정 작업 후보</h3>
    <p>보안 공지 수는 수정 작업 수와 다릅니다. 상위 선언 기준 {groups.length}개 묶음이며, 한 공지가 여러 작업에 포함될 수 있습니다. 원본 공지와 우선순위는 그대로 유지됩니다.</p>
    <details><summary>상위 패키지별 묶음 확인</summary>
      <ul>{groups.map((g, i) => <li key={i}><strong>{g.label}</strong> · <code className="finding-location">{g.file}</code>
        <p>{[...g.packages].join(', ')} · 관련 공지 {g.advisories.size}개</p></li>)}</ul>
      <p>상위 패키지 변경 후 실제 설치 버전과 개별 공지의 수정 버전을 대조하고, 빌드·테스트를 거쳐 같은 프로젝트를 재검사하세요. 묶음 하나의 변경으로 모든 문제가 해결된다고 보장하지 않습니다.</p>
    </details>
  </section>;
}
