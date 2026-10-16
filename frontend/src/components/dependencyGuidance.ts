import type { RiskFinding } from '../types/securityReview';

export const unconfirmed = '확인하지 못했습니다';
export function knownDependencyValue(value?: string | null): string | null {
  const text = value?.trim();
  return !text || /^(unknown|null|n\/a)$/i.test(text) || /<[^>]+>/.test(text) ? null : text;
}

// Also protects legacy stored advice/identifiers from leaking internal sentinel strings.
export function dependencyText(value?: string | null): string {
  return value?.replace(/<(?:unresolved-[^>]*|non-registry-spec)>|\b(?:unknown|null|N\/A)\b/gi, unconfirmed) || unconfirmed;
}

export function incompleteDependency(finding?: RiskFinding): boolean {
  return finding?.source === 'DEPENDENCY' && finding.reasonCode === 'UNRESOLVED_VERSION' && !finding.dependency;
}

export function dependencyGuidance(finding: RiskFinding) {
  const name = knownDependencyValue(finding.packageName);
  const files = finding.sourceFiles.map(knownDependencyValue).filter((value): value is string => !!value);
  const gradle = files.some(file => /(?:build\.gradle(?:\.kts)?|gradle\.lockfile|\.versions\.toml)$/.test(file));
  const npm = finding.ecosystem === 'NPM';
  const location = files.length ? files.join(', ') : unconfirmed;
  const declaration = knownDependencyValue(finding.version);
  return {
    name, files, location, declaration,
    title: name ? '이 라이브러리의 정확한 버전을 확인해 주세요.' : '라이브러리 정보를 끝까지 확인하지 못했습니다.',
    reason: !name ? '라이브러리 관련 설정은 찾았지만 이름과 버전을 현재 정적 분석 범위에서 결정하지 못했습니다.'
      : !declaration ? '파일에 직접 버전이 없거나 다른 설정에서 가져올 수 있어 실제 사용 버전을 결정하지 못했습니다.'
      : '선언된 값만으로 실제 사용하는 정확한 버전을 결정하지 못했습니다. 버전 범위나 다른 설정의 참조일 수 있습니다.',
    places: npm ? 'package.json에서 이름을 찾고 package-lock.json, yarn.lock 또는 pnpm-lock.yaml에서 설치 버전을 확인하세요.'
      : gradle ? 'build.gradle 또는 build.gradle.kts를 확인하세요. 별칭·변수를 사용한다면 gradle/libs.versions.toml, gradle.properties, gradle.lockfile도 확인하세요.'
      : 'pom.xml의 해당 라이브러리를 확인하세요. 버전이 없으면 properties, parent 및 dependencyManagement에서 가져오는지 확인하세요.',
    nameHint: npm ? '등록된 라이브러리 이름 (예: lodash 또는 @scope/name)'
      : '그룹과 이름을 함께 입력 (예: org.example:library)',
    steps: [files.length ? `${location} 파일을 열어 주세요.` : '프로젝트의 라이브러리 설정 파일을 찾아 주세요. 저장된 파일 위치는 확인하지 못했습니다.',
      name ? `${name} 항목의 실제 사용 버전을 찾으세요.` : '사용 중인 라이브러리의 등록된 이름과 정확한 버전을 찾으세요.',
      '값을 알게 되면 추가 정보로 조회할 수 있습니다. 입력값은 소스에서 검증된 값이 아닙니다.',
      '알려진 문제가 확인되면 제공된 수정 버전과 호환성을 검토하세요. 수정 버전이 없으면 공식 보안 공지를 확인하세요.',
      '실제 프로젝트를 수정하고 빌드·기능 테스트 후 SecureDeploy로 다시 검사하세요.'],
  };
}
