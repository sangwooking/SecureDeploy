import type { DependencyComponent } from '../types/securityReview';

const environments: Record<string, string> = {
  DEVELOPMENT_FILENAME_HINT: '파일명상 개발·테스트용 후보', PRODUCTION_FILENAME_HINT: '파일명상 운영용 후보',
  PROJECT_DECLARATION: '프로젝트 의존성 선언', OPTIONAL_DECLARATION: '선택 설치 선언',
  BUILD_DECLARATION: '빌드 도구 선언', DEVELOPMENT_GROUP_DECLARATION: '개발·테스트 그룹 선언',
  PRODUCTION_GROUP_DECLARATION: '운영 그룹 선언', GROUP_DECLARATION: '의존성 그룹 선언', UNKNOWN: '설치 환경 확인 불가',
};
export function PythonDependencyDetails({ locations }: { locations: DependencyComponent[] }) {
  return <details className="action-details"><summary>Python 선언 근거와 수정 위치 확인</summary>
    <p>확인한 버전은 파일의 정적 선언입니다. 실제 설치·운영 사용 여부와 간접 의존성 전체는 확인하지 않았습니다.</p>
    {!locations.length && <p>이 이력에는 추가 선언 근거가 없습니다. requirements 또는 pyproject 설정에서 실제 설치 입력을 확인하세요.</p>}
    {locations.map((c, index) => <section key={`${c.sourceFile}:${c.line}:${index}`} className="dependency-context">
      <h4>{environments[c.python?.environment ?? 'UNKNOWN'] ?? environments.UNKNOWN}</h4>
      <p className="finding-location">의존성 선언 위치: <code>{c.sourceFile}{c.line > 0 ? `:${c.line}` : ''}</code></p>
      {c.python && <>
        <p className="finding-location">설치 입력으로 검토한 파일: <code>{c.python.rootManifest}</code></p>
        <p>버전 근거: {c.python.versionOrigin === 'CONSTRAINT_PIN' ? '연결된 제약 파일의 고정 버전'
          : c.python.versionOrigin === 'PINNED_DECLARATION' ? '의존성의 고정 버전 선언' : '추가 확인 필요'} · 선언: {c.python.declaration ?? '버전 미기록'}</p>
        {c.python.constraints.map((p, i) => <p key={i} className="finding-location">함께 확인할 제약 파일: <code>{p.file}:{p.line}</code></p>)}
        {c.python.extras.length > 0 && <p>요청 extras: {c.python.extras.join(', ')} · 추가 패키지 목록은 미확인</p>}
        {c.python.markerStatus !== 'NONE' && <p className="review-caution">설치 환경 조건은 평가하지 않았습니다. {c.python.markerVariables.join(', ') || '조건 구문 미확인'}</p>}
        {c.python.limitations.map((note, i) => <p key={i}>{note}</p>)}
      </>}
    </section>)}
    <p>실제 배포에서 사용하는 requirements·pyproject와 제약 파일을 확인해 수정하세요. 호환성·기능 테스트와 설치 결과 확인 후 같은 프로젝트를 다시 검사하세요.</p>
  </details>;
}
