import { useState } from 'react';
import type { DeploymentAnalysis } from '../types/deploymentAnalysis';

const statusText = (value: string) => ({ PARSED: '설정 구조 확인', PARTIAL: '일부 범위 확인',
  NOT_APPLICABLE: '확인된 설정 대상 없음', PARSE_FAILED: '파싱 실패 또는 미지원 문법',
  LIMIT_EXCEEDED: '자원 제한으로 확인하지 못함', NOT_RUN: '검사하지 못함' }[value] ?? '확인하지 못함');
const scopeText = (scope: string) => scope === 'DEVELOPMENT_NAME_HINT_NOT_RUNTIME_PROOF' ? '개발용 이름 단서 · 실제 적용 환경 미확인'
  : scope === 'MODULE_REFERENCE_ACTIVATION_UNKNOWN' ? 'Django 설정 모듈 참조 확인 · 운영 적용 미확인'
  : scope === 'DJANGO_STRUCTURE_ACTIVATION_UNKNOWN' ? 'Django 설정 구조 확인 · 적용 환경 미확인' : scope;
const limits: Record<string, string> = {
  DEFAULT_FINAL_STAGE_ONLY_COMPOSE_TARGET_AND_USER_NOT_MERGED:'기본 최종 stage 선언만 확인했습니다. Compose target·실행 user override는 병합하지 않았습니다.',
  IMAGE_CONTENTS_LAYERS_SBOM_AND_REGISTRY_NOT_INSPECTED:'이미지·레이어·캐시·SBOM·registry 내부는 검사하지 않았습니다. 태그나 digest는 패치 완료의 증명이 아닙니다.',
  BUILD_SECRET_MOUNT_NOT_COPY_OR_LOG_PROTECTION:'secret mount 선언만 확인했습니다. 내용을 복사하거나 출력하는 후속 작업까지 보호된다는 뜻은 아닙니다.',
  COPY_CONTEXT_DOCKERIGNORE_AND_SYMLINKS_NOT_INSPECTED:'COPY 대상·.dockerignore·실제 빌드 context와 심볼릭 링크는 확인하지 못했습니다.',
  LIMITED_ENV_NOT_COMPLETE_DOCKERFILE_VALIDATION:'지원 ENV·사용자·일부 지시어 선언 검사이며 Dockerfile 전체 검증이나 이미지 빌드가 아닙니다.',
  DOCKER_ENV_SYNTAX_OR_BUDGET_NOT_RESOLVED:'ENV escape·heredoc·문법 또는 기록 예산을 확인하지 못했습니다. 기존 패턴 경고는 보수적으로 유지합니다.',
  WORKFLOW_DECLARATIONS_NOT_RUNNER_OR_ATTACK_PROOF:'Workflow 선언만 검사했습니다. Actions·shell을 실행하거나 공격 성공을 확인하지 않았습니다.',
  ORGANIZATION_TOKEN_SECRETS_AND_ENVIRONMENT_APPROVAL_UNKNOWN:'조직 권한·실제 token·secret 값·환경 승인·runner 격리는 미확인입니다.',
  EXTERNAL_ACTION_AND_REUSABLE_IMPLEMENTATIONS_NOT_LOADED:'외부 Action·재사용 Workflow의 코드는 불러오거나 실행하지 않았습니다.',
  INVALID_OR_UNSUPPORTED_WORKFLOW_YAML:'Workflow YAML이 잘못됐거나 alias·merge·태그·중복 키 등 미지원 구문이 있습니다.',
  WORKFLOW_EVENTS_UNKNOWN:'Workflow 이벤트를 확인하지 못했습니다.',
  WORKFLOW_EVENT_CHAIN_NOT_RESOLVED:'workflow_run·workflow_call의 실행·권한 연결은 미지원입니다.',
  REUSABLE_WORKFLOW_NOT_RESOLVED:'재사용 Workflow 내부의 실제 작업·권한은 미확인입니다.',
  WORKFLOW_STEPS_UNKNOWN:'지원하는 steps 구조가 아니어서 작업을 확인하지 못했습니다.',
  JOB_IDENTIFIER_UNKNOWN:'Job 식별자 형식을 확인하지 못해 해당 작업을 분석하지 않았습니다.',
  JOB_CONDITION_MATRIX_DEPENDENCY_OR_SHELL_UNKNOWN:'조건·matrix·job 의존관계·container·기본 shell의 실제 효과는 미확인입니다.',
  STEP_CONDITION_WORKSPACE_OR_SHELL_UNKNOWN:'Step 조건·실행 디렉터리·shell이 달라 실행 연결을 보류했습니다.',
  EXTERNAL_ACTION_SIDE_EFFECTS_UNKNOWN:'외부 Action이 이후 파일·실행 환경을 바꿀 수 있어 추가 연결을 보류했습니다.',
  SHELL_COMMAND_AND_ENV_FLOW_NOT_FULLY_MODELED:'복잡한 shell·eval·환경변수의 후속 사용은 완전히 분석하지 못했습니다.',
  PROJECT_EXECUTION_PRIVILEGE_OR_DISPATCH_NOT_PROVEN:'프로젝트 실행 선언만으로 실제 요청 전달·권한·자격증명 접근을 확정하지 않았습니다.',
  DECLARATIONS_ONLY_RUNTIME_AND_OVERRIDES_UNKNOWN: '파일의 선언만 검사했습니다. 실제 활성 환경과 추가 override는 확인하지 않았습니다.',
  SUPPLEMENTAL_REVIEW_NOT_RISK_OR_SCORE: '새 설정 검토 항목은 기존 점수·배포 판단·반드시 처리 건수에 합산하지 않습니다.',
  INVALID_OR_UNSUPPORTED_YAML: 'YAML을 읽지 못했거나 alias·merge·태그·중복 키 등 미지원 구조가 있습니다.',
  CONFIG_RESOURCE_LIMIT: '설정 파일 크기·구조·시간·기록 수 제한으로 일부 검사를 완료하지 못했습니다.',
  CONFIG_RESOURCE_OR_PATH_LIMIT: '파일 수·전체 크기·시간 또는 민감한 경로 제한으로 검사하지 못했습니다.',
  DYNAMIC_OR_UNSUPPORTED_SETTING: '환경변수나 지원하지 않는 값이 있어 최종 값을 확인하지 못했습니다.',
  EXTERNAL_INCLUDE_NOT_RESOLVED: '외부 include 파일을 읽거나 병합하지 않았습니다.',
  SERVICE_ACTIVATION_OR_REFERENCE_UNRESOLVED: '서비스 profile·외부 설정·상속의 적용 여부는 미확인입니다.',
  USER_OVERRIDES_IMAGE_DEFAULT_BUILD_TARGET_AND_RUNTIME_NOT_RESOLVED: 'Compose user는 이미지 기본 사용자를 바꿀 수 있습니다. 실제 target과 override는 미확인입니다.',
  DOCKERFILE_TARGET_IMAGE_AND_COMPOSE_USER_NOT_MERGED: 'Dockerfile 기본 최종 stage와 Compose 실행 구성을 하나의 실제 실행 사용자로 합치지 않았습니다.',
  MOUNT_CONTENTS_AND_SYMLINKS_NOT_INSPECTED: '마운트 경로의 실제 파일·심볼릭 링크·내용을 열거나 검사하지 않았습니다.',
  OTHER_SERVICE_OPTIONS_NOT_SECURITY_VALIDATED: '기록한 서비스 보안 항목 외의 옵션은 보안 검증하지 않았습니다.',
  ENVIRONMENTS_NOT_MERGED_OR_ACTIVATED: 'Cloudflare 환경별 선언은 분리해 기록했으며 상속·활성 환경을 추측하지 않았습니다.',
  VARS_VALUES_OMITTED_NOT_ASSUMED_SECRET: '변수의 실제 값은 보관하지 않습니다. API 관련 이름만으로 비밀정보라고 판단하지 않습니다.',
  BINDINGS_ROUTES_AND_PLATFORM_SECRET_VALUES_NOT_VERIFIED: 'binding·route 선언 구조만 읽었습니다. 플랫폼에 저장된 비밀값·접근 권한·외부 노출은 미검증입니다.',
  INVALID_OR_UNSUPPORTED_WRANGLER: 'Wrangler 형식을 파싱하지 못했거나 지원 범위를 벗어난 구조입니다.',
  IMPORTS_AND_BASE_SETTINGS_NOT_MERGED: '다른 settings 모듈을 실행하거나 import해 기본 설정과 병합하지 않았습니다.',
  MISSING_SETTINGS_DEFAULTS_NOT_INFERRED: '선언이 없는 설정의 기본값과 환경값을 추측하지 않았습니다.',
  BASE_SETTINGS_IMPORT_UNRESOLVED: '기본 설정 import의 값을 확인하지 못했습니다. 이후 명시적 대입만 기록했습니다.',
  DYNAMIC_SETTINGS_WRITE_UNRESOLVED: '동적 코드나 호출이 설정을 바꿀 수 있어 값을 확정하지 않았습니다.',
  CONDITIONAL_SETTINGS_UNRESOLVED: '조건에 따라 값이 달라질 수 있습니다. 양쪽에서 같은 값인 경우만 정적으로 기록했습니다.',
  SETTINGS_ROLE_NOT_INSPECTED: 'Python 파일을 읽지 못해 Django 설정 역할인지도 확인하지 못했습니다.',
  DJANGO_SETTINGS_NOT_RUN: 'Python 설정 검사가 실행되지 않아 Django 배포 설정을 확인하지 못했습니다.',
  SOURCE_LIMITS_OR_SENSITIVE_PATHS_OMITTED: '소스 제한 또는 민감한 경로로 선택하지 못한 Python 설정 후보가 있습니다.',
  CONFIG_FINDING_LIMIT: '검토 항목 수 상한으로 일부 항목을 표시하지 못했습니다.',
};
const limitationText = (value: string) => limits[value] ?? '추가 미확인 범위가 있습니다. 기술 정보를 확인하세요.';

export function DeploymentAnalysisSection({ snapshot, compact = false }: { snapshot?: DeploymentAnalysis | null; compact?: boolean }) {
  const [page, setPage] = useState(0);
  if (!snapshot) return compact ? null : <section className="analysis-coverage-brief"><h3>서버·배포 설정 검사</h3><p>이 이력에는 설정 구조 검사 기록이 없습니다. 과거 결과를 추측해 채우지 않습니다.</p></section>;
  const unknown = snapshot.files.reduce((sum, f) => sum + f.observations.filter(o => o.valueStatus !== 'STATIC').length, 0);
  const missed = snapshot.files.filter(f => f.status !== 'PARSED').length;
  const current = Math.min(page, Math.max(0, Math.ceil(snapshot.findings.length / 6) - 1));
  return <section className={compact ? 'analysis-coverage-brief' : 'server-analysis-section'} aria-label={compact ? '서버·배포 설정 요약' : '서버·배포 설정 검사'}>
    <h3>서버·배포 설정 검사</h3>
    <p>{statusText(snapshot.status)} · 별도 검토 항목 {snapshot.findings.length}건 · 값 미확인 {unknown}건 · 읽지 못한 파일 {missed}개</p>
    <p>설정 선언과 실제 운영 적용은 다릅니다. 항목이 없어도 전체 배포 환경이 안전하다는 뜻은 아닙니다.</p>
    <p className="review-caution">새 설정 검토 항목은 기존 점수·배포 판단·반드시 처리 건수에 합산하지 않습니다. 기존 Compose 특권·host 네트워크 경고는 원래 룰 결과에서 확인하세요.</p>
    {!compact && <>
      <div className="vulnerability-list">{snapshot.findings.slice(current * 6, current * 6 + 6).map(f => <article key={f.findingId} className="vulnerability-item action-finding">
        <span className="risk-badge risk-review_required">설정 선언 · 추가 확인 필요</span><h4>{f.title}</h4>
        <p className="finding-location">확인할 파일: {f.filePath}:{f.line}</p>
        <p>{scopeText(f.scope)} · {f.setting}</p>
        <h4>왜 확인해야 하나요?</h4><p>{f.reason}</p>
        <h4>어떻게 수정하나요?</h4><p>{f.recommendation}</p>
        <h4>수정 후 확인</h4><ol>{f.verificationSteps.map(step => <li key={step}>{step}</li>)}</ol>
        <details className="technical-details"><summary>설정 근거와 한계</summary><p>{f.ruleId} · {f.sourceType} · {f.priority}</p>
          <p className="finding-location">{f.findingId}</p><p>정적 선언: {f.valueSummary}</p>
          <p>실제 적용 환경과 공격 성공은 검증하지 않았습니다. 비교 정책: {f.comparisonPolicy}. 미표시를 해결로 계산하지 않습니다.</p>
        </details>
      </article>)}</div>
      {snapshot.findings.length > 6 && <nav className="finding-pagination" aria-label="설정 검토 항목 페이지">
        <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)}>이전</button><span>{current + 1} / {Math.ceil(snapshot.findings.length / 6)}</span>
        <button type="button" disabled={(current + 1) * 6 >= snapshot.findings.length} onClick={() => setPage(current + 1)}>다음</button>
      </nav>}
      <details className="coverage-details"><summary>설정 파일별 검사 범위 ({snapshot.files.length})</summary>
        {snapshot.files.map((file, i) => <details key={i} className="technical-details"><summary className="finding-location">{file.filePath} · {file.format} · {statusText(file.status)}</summary>
          <ul className="coverage-file-list">{file.observations.map((o, j) => <li key={j}><code className="finding-location">{o.setting} · {file.format === 'WRANGLER' ? '문서 단위' : `${o.line}행`}</code>
            <span>{scopeText(o.scope)} · {o.valueStatus === 'STATIC' ? '정적 선언 확인' : '값 확인 불가'}</span><span>{o.valueSummary}</span></li>)}</ul>
          <ul>{file.limitations.map(l => <li key={l}>{limitationText(l)}</li>)}</ul>
        </details>)}
      </details>
      <ul>{snapshot.limitations.map(l => <li key={l}>{limitationText(l)}</li>)}</ul>
      <details className="technical-details"><summary>분석기 정보</summary><p>{snapshot.analyzerVersion} · schema {snapshot.schemaVersion}</p>
        <ul>{snapshot.limitations.map(l => <li key={l}>{l}</li>)}</ul></details>
    </>}
  </section>;
}
