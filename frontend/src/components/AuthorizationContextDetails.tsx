import type { AnalysisLocation, AuthorizationDetails } from '../types/serverAnalysis';

const labels: Record<string,string> = {
  UNKNOWN:'확인하지 못함', DECLARED_LOGIN_REQUIRED:'로그인 요구 선언 확인', DECLARED_STAFF_REQUIRED:'직원·관리자 역할 요구 선언 확인',
  DECLARED_PUBLIC:'공개 접근 선언 확인', NOT_ESTABLISHED:'객체별 접근 권한을 판단하지 못함',
  PROTECTION_EVIDENCE_NOT_FULL_ASSURANCE:'조회 범위 또는 차단 근거 있음 · 전체 권한 보증은 아님', RISK_LOGIC_CANDIDATE:'비교·차단 방향의 추가 검토 후보',
  NO_RESOURCE_ACCESS_TRACED:'지원 범위에서 연결한 리소스 접근 없음',
  VIEW_CLASS:'View 클래스 선언', VIEW_DECORATOR:'함수 View 선언', ACTION_DECORATOR:'해당 action 선언', GET_PERMISSIONS:'get_permissions의 제한된 정적 반환',
  GLOBAL_CANDIDATE_ACTIVATION_UNKNOWN:'전역 설정 후보 · 활성 모듈·덮어쓰기 미확인',
  DJANGO_DECORATOR:'Django 인증·권한 decorator', DJANGO_MIXIN:'Django 접근 제어 mixin 선언', CUSTOM_RESOURCE_METHOD:'사용자 정의 리소스 조회 메서드',
  IsAuthenticated:'로그인 요구 · 객체 소유권 검사는 아님', IsAdminUser:'직원 역할 요구 · 객체 소유권 검사는 아님', AllowAny:'공개 접근 허용 선언',
  IsAuthenticatedOrReadOnly:'요청 작업별 로그인 정책 · 추가 문맥 필요', DjangoModelPermissions:'모델 권한 정책 · 객체 범위 별도 확인',
  DjangoObjectPermissions:'객체 권한 정책 선언 · backend·구현 미검증', CUSTOM_PERMISSION_UNKNOWN:'사용자 정의 권한 · 동작 미확인',
  LOGIN_REQUIRED:'로그인 요구 decorator', STAFF_REQUIRED:'직원 역할 요구 decorator', PERMISSION_REQUIRED:'권한 요구 decorator · 실제 권한 문맥 미확인',
  CUSTOM_QUERYSET:'get_queryset 정의 위치 · 호출·반환 경로 별도 확인', CUSTOM_GET_OBJECT:'get_object 정의 위치 · 객체 권한 검사 별도 확인',
  MIXIN_EXECUTION_UNKNOWN:'mixin 순서·실행 동작 미확인',
  QUERYSET_DECLARATION:'조회 범위 구성', RESOURCE_LOOKUP:'리소스 조회 호출', WRITE:'리소스 저장 호출', DELETE:'리소스 삭제 호출', OBJECT_PERMISSION_CALL:'객체 권한 검사 호출',
  USER_SCOPE_QUERY_EVIDENCE:'요청 사용자와 연결된 모델 필드로 조회 범위를 제한한 근거',
  OWNER_GUARD_EVIDENCE:'소유자 비교와 거부 분기 근거', ROLE_GUARD_EVIDENCE:'역할 비교와 거부 분기 근거',
  OBJECT_AUTHORIZATION_NOT_ESTABLISHED:'이 객체의 접근 권한은 판단하지 못함', OBJECT_CHECK_CALLED_POLICY_UNKNOWN:'객체 검사 호출 확인 · 적용 정책의 보호 효과 미확인',
  INVERTED_OWNER_REJECTION_CANDIDATE:'소유자 일치 시 차단 후 다른 경로에서 변경 · 의도 확인 필요', ACCESS_FLOW_UNRESOLVED:'조회 식별자 또는 실행 경로 일부 미확인',
  AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED:'실제 인증 설정·미들웨어·실행 환경은 확인하지 않았습니다.',
  AUTHENTICATION_IS_NOT_OBJECT_AUTHORIZATION:'로그인 요구는 다른 사용자 정보에 대한 접근 차단을 보증하지 않습니다.',
  GLOBAL_SETTINGS_SELECTION_AND_OVERRIDES_UNKNOWN:'전역 설정의 선택·상속·환경별 덮어쓰기를 확인하지 못했습니다.',
  CUSTOM_PERMISSION_EXECUTION_NOT_VERIFIED:'get_permissions의 지원되는 정적 반환만 읽었으며 실행하지 않았습니다.',
  CUSTOM_DISPATCH_AUTH_EXECUTION_UNKNOWN:'사용자 정의 dispatch·initial이 권한 실행에 미치는 영향은 미확인입니다.',
  INHERITED_RESOURCE_AND_PERMISSION_METHODS_NOT_EXECUTED:'프레임워크의 상속 메서드를 실행하거나 자동 보호를 추정하지 않았습니다.',
  MIXIN_ORDER_AND_DISPATCH_EXECUTION_UNKNOWN:'mixin의 순서와 실제 dispatch 실행 여부는 미확인입니다.',
  OBJECT_PERMISSION_CALL_POLICY_NOT_VERIFIED:'객체 검사 호출이 있더라도 사용한 permission의 객체 보호 효과는 별도 확인이 필요합니다.',
  CUSTOM_OBJECT_PERMISSION_METHOD_UNKNOWN:'사용자 정의 객체 검사 메서드의 전체 동작은 미확인입니다.',
  PERMISSION_DECORATOR_ORDER_UNKNOWN:'decorator 적용 순서로 최종 권한 설정을 확인하지 못했습니다.',
  PERMISSION_POLICY_REQUIRES_ADDITIONAL_CONTEXT:'사용자 정의·작업별·객체 권한 정책은 추가 문맥이 필요합니다.',
  MODEL_MANAGER_AND_PROPERTIES_NOT_VERIFIED:'모델의 사용자 정의 Manager·속성 동작은 미검증입니다.',
  RESOURCE_PRIMARY_KEY_NOT_VERIFIED_AS_OWNER_KEY:'리소스 ID와 사용자 ID의 비교를 소유자 관계로 인정하지 않았습니다.',
  AUTH_DETAIL_LIMIT:'문맥 기록 수 제한에 도달하여 일부 근거를 기록하지 못했습니다.',
  AUTH_VALUE_FLOW_UNRESOLVED:'미확인 호출·변경·반환으로 사용자 또는 리소스 관계의 일부를 추적하지 못했습니다.',
  PERMISSION_INHERITANCE_OR_DISPATCH_UNKNOWN:'상속 또는 사용자 정의 진입 처리 때문에 실제 적용 권한을 확인하지 못했습니다. 선언과 활성 정책을 구분해야 합니다.',
};
const text=(v:string)=>labels[v]??'지원 범위 밖이거나 추가 확인이 필요한 처리';
const place=(v:AnalysisLocation)=>`${v.filePath}:${v.line} · ${v.functionName}`;

export function AuthorizationContextDetails({details}:{details:AuthorizationDetails}) {
  return <div className="authorization-context-details">
    <p><strong>로그인·역할</strong> {text(details.authenticationStatus)}</p>
    <p><strong>이 정보에 접근할 권한</strong> {text(details.objectAuthorizationStatus)}</p>
    <p>로그인 확인과 리소스 접근 권한은 별개입니다. 검사 위치가 없다는 이유만으로 접근 권한 취약점으로 판단하지 않습니다.</p>
    <h4>어떤 권한 선언을 참고했나요?</h4><p>{text(details.permissionSource)}</p>
    <ul className="coverage-file-list">{details.permissionDeclarations.map((d,i)=><li key={i}><span>{text(d.source)}</span>
      <code className="finding-location">{place(d.location)}</code><span>{d.permissions.length?d.permissions.map(text).join(' · '):'권한 목록이 비어 있는 선언'}</span></li>)}</ul>
    <h4>어떤 정보에 접근하나요?</h4>
    {!details.accesses.length&&<p>현재 지원 범위에서 연결한 조회·변경 호출이 없습니다. 전체 기능에 접근 제어가 있다는 뜻은 아닙니다.</p>}
    <ul className="coverage-file-list">{details.accesses.map((a,i)=><li key={i}><strong>{text(a.operation)}</strong><code className="finding-location">{place(a.location)}</code>
      <span>{text(a.conclusion)}</span><span className="finding-location">조회 위치: {place(a.resourceLocation)}</span>
      {a.identifierInputs.map((s,j)=><span key={j} className="finding-location">요청 값 전달: {place(s)}</span>)}
      {a.checks.map((s,j)=><span key={`c${j}`} className="finding-location">확인한 검사: {place(s)}</span>)}
      {a.limitations.map(l=><span key={l}>{text(l)}</span>)}
    </li>)}</ul>
    <details className="technical-details"><summary>사용자·조건 비교 위치와 분석 한계</summary>
      <ul>{[...details.principalReferences,...details.ownershipComparisons].map((l,i)=><li key={i}><code className="finding-location">{place(l)}</code> · {l.kind}</li>)}</ul>
      <ul>{details.limitations.map(l=><li key={l}>{text(l)}</li>)}</ul>
      <p>기술 상태: {details.authenticationStatus} · {details.objectAuthorizationStatus} · {details.permissionSource}</p>
    </details>
    <p>직접 확인: 로컬에서 두 사용자와 소유·비소유 객체를 준비하고 익명·일반·관리자 계정의 조회·변경·삭제 허용/거부를 검증하세요. 실패한다면 사용자별 조회 범위나 명시적 객체 권한 검사를 보완한 뒤 다시 검사하세요.</p>
  </div>;
}
