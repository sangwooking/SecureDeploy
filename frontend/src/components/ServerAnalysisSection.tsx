import { useState } from 'react';
import type { AnalysisLocation, ServerAnalysisSnapshot } from '../types/serverAnalysis';
import { DeploymentAnalysisSection } from './DeploymentAnalysisSection';
import { AuthorizationContextDetails } from './AuthorizationContextDetails';
import { TokenSecurityDetails } from './TokenSecurityDetails';
import { ExposureDetails } from './ExposureDetails';
import { ServiceStabilityDetails } from './ServiceStabilityDetails';
import { JavaSqlAnalysisSection } from './JavaSqlAnalysisSection';
import { SupabaseAnalysisSection } from './SupabaseAnalysisSection';

const entryStageLabels: Record<string,string>={
  RATE_LIMIT_DECLARATION:'요청 제한 선언 · 적용·실제 차단 증명 아님',
  RATE_LIMIT_NOT_APPLICABLE:'이 요청 경로에 해당 제한이 선행하지 않음',
  RATE_LIMIT_APPLICATION_UNKNOWN:'요청 제한의 적용·합성·설정 변경 관계 미확인',
  RATE_LIMIT_DEFAULT_STOP_BOUND:'지원 버전의 기본 초과 종료 계약 연결 · 운영 효과 미확인',
  RATE_LIMIT_ZERO_BLOCKS_BOUND:'지원 버전의 0 설정은 전체 차단 · 무제한 허용 아님',
  RATE_LIMIT_BLOCKING_UNKNOWN:'요청 제한의 키·콜백·차단 효과 미확인',
  RATE_LIMIT_EXPLICIT_BYPASS:'항상 건너뛰기 또는 초과 후 다음 작업 진행 선언',
  RATE_LIMIT_BYPASS_TO_WORK:'제한을 건너뛰는 선언과 서버 작업 연결 · 실제 남용·비용 미검증',
  CORS_FIXED_ORIGIN:'고정 Origin 선언 · 인증·인가 증명 아님',CORS_WILDCARD_DECLARED:'전체 Origin 선언 · 공개 용도는 별도 확인',
  CORS_WILDCARD_CREDENTIALS_BLOCKED:'wildcard와 credentials 조합 · 브라우저의 credential 응답 접근 제한',
  CORS_POLICY_NOT_APPLICABLE:'이 응답 경로에 해당 CORS 설정이 선행하지 않음',
  CORS_REFLECTION_CONTEXT_UNKNOWN:'Origin 반사 선언 · 응답 민감도 미확인',
  SENSITIVE_REFLECTED_CREDENTIAL_RESPONSE:'민감 응답 후보와 Origin 반사·credentials 선언 연결',
  WEB_POLICY_UNRESOLVED:'설정·미들웨어 범위·변경 관계 미확인',WEB_POLICY_COMPOSITION_UNKNOWN:'복수 보안 미들웨어의 합성 효과 미확인',
  SESSION_COOKIE_ATTRIBUTES:'세션 쿠키 속성 선언 · 실제 발급·인증 미검증',SESSION_HTTPONLY_EXPLICITLY_DISABLED:'세션 쿠키의 명시적 HttpOnly 해제 선언',
  CSRF_READ_ONLY_LOCAL_BODY:'지원하는 로컬 본문에서 업무 상태 변경 미관찰',CSRF_EXACT_ORIGIN_CONSTRAINT:'상태 변경 전 정확한 Origin 차단 조건 선언 · 전체 CSRF 보호 미검증',
  CSRF_CONTEXT_UNVERIFIED:'인증 방식·상태 변경·CSRF 보호를 추가 확인해야 함',
  ENTRY_REGISTERED:'요청 handler의 정적 등록·Router 연결 확인',CALL_LINKED:'확인된 함수에서 Router 반환 연결',
  CALLBACK_BOUND:'Passport 콜백 등록 선언 확인 · 요청 실행은 미확인',
  AUTHENTICATOR_REFERENCED:'같은 파일에서 등록한 인증 전략 참조 확인 · 실행은 미확인',
  CALL_TARGET_UNKNOWN:'등록된 콜백 대상을 확인하지 못함',EXTERNAL_IMPLEMENTATION_UNKNOWN:'외부 인증 전략 등록은 미확인'
};

const labels: Record<string, string> = {
  RATE_LIMIT_VERSION_OPTIONS_OR_STORE_UNKNOWN:'제한 라이브러리 버전·설정·저장소 계약 미확인',
  RATE_LIMIT_SCOPE_LIMIT:'요청 제한 적용 범위 추적 상한',
  UPSTASH_RATE_LIMIT_EXECUTION_CONTRACT_NOT_SUPPORTED:'Upstash SDK 객체·요청별 결과·차단 분기 연결 미지원',
  EXTERNAL_GATEWAY_WAF_AND_DEPLOYMENT_UNKNOWN:'외부 Gateway·WAF·실제 배포 보호 미확인',
  RATE_BUDGET_BUSINESS_REQUIREMENTS_UNKNOWN:'업무별 허용 횟수·자원 예산 요구사항 미확인',
  AUTHENTICATION_AND_DISTRIBUTED_ABUSE_NOT_PROVEN:'인증 성공·분산된 계정 남용 방어는 미검증',
  PROXY_HOPS_HEADER_REPLACEMENT_AND_IP_NORMALIZATION_UNKNOWN:'프록시 홉·헤더 교체·IP 정규화 미확인',
  IP_DECLARED_PROXY_UNKNOWN:'IP 기반 키 선언 · 실제 프록시 문맥 미확인',GLOBAL_CONSTANT_KEY:'전역 고정 키 · 사용자별 제한 아님',
  REQUEST_HEADER_KEY_UNVERIFIED:'요청 헤더 기반 키 · 신뢰된 식별자 여부 미확인',KEY_UNKNOWN:'제한 식별자·사용자 신원 미확인',
  MEMORY_STORE_PROCESS_LOCAL_DECLARATION:'프로세스 로컬 MemoryStore 기본 선언',
  STORE_CONNECTIVITY_AND_MULTI_INSTANCE_EFFECT_UNKNOWN:'저장소 연결·다중 인스턴스 공유 효과 미검증',
  STORE_ERROR_FAIL_OPEN_DECLARED:'저장소 오류 시 요청 통과 선언 · 업무 적합성 별도 확인',
  STORE_ERROR_NOT_PASSED_BY_DEFAULT:'저장소 오류 시 기본 통과하지 않음 · 운영 장애 처리 미검증',
  SKIP_ALWAYS_TRUE:'항상 제한을 건너뛰는 콜백 선언',EXCEEDED_HANDLER_CALLS_NEXT:'초과 handler가 다음 작업 진행 함수를 호출',
  OPERATION_COST_AND_SENSITIVITY_NOT_PROVEN:'작업의 실제 비용·민감도·남용 성공은 미확인',
  WEB_MIDDLEWARE_VERSION_OR_OPTIONS_UNKNOWN:'보안 미들웨어의 버전·옵션·출처를 확인하지 못함',
  WEB_MIDDLEWARE_SCOPE_LIMIT:'보안 미들웨어 적용 범위 추적 상한',
  NEXT_CORS_CSRF_COOKIE_CONTRACT_NOT_EVALUATED:'Next.js CORS·CSRF·쿠키 보호 계약은 이번 범위에서 미검사',
  DECLARED_POLICY_NOT_BROWSER_OR_AUTHENTICATION_PROOF:'저장소 선언 근거 · 실제 브라우저 동작·인증 성공의 증명 아님',
  PROXY_TLS_AND_DEPLOYMENT_UNKNOWN:'프록시·HTTPS·실제 배포 적용은 미확인',
  MIDDLEWARE_SCOPE_OR_MUTATION_UNKNOWN:'미들웨어 적용 순서·범위 또는 설정 변경 미확인',
  SESSION_COOKIE_REFERENCE_NOT_AUTHENTICATION_SUCCESS:'세션 참조 확인 · 실제 쿠키 발급·인증 성공은 미검증',
  COOKIE_HTTPONLY_DEFAULT_ENABLED:'지원 버전의 기본 HttpOnly 활성화 선언',
  COOKIE_HTTPONLY_ENABLED:'HttpOnly 활성화 선언',COOKIE_HTTPONLY_DISABLED:'HttpOnly 해제 선언',
  COOKIE_SECURE_ENABLED:'Secure 활성화 선언 · 실제 HTTPS는 미검증',
  COOKIE_SECURE_DISABLED:'Secure 해제 선언 · 전송 환경 추가 확인',
  COOKIE_SECURE_DEFAULT_DISABLED:'지원 버전의 기본 Secure 해제 · 전송 환경 추가 확인',
  COOKIE_SAMESITE_DECLARED_NOT_CSRF_PROOF:'SameSite 선언 · 전체 CSRF 보호 증명 아님',
  COOKIE_SAMESITE_UNSET:'SameSite 명시 설정 미확인',COOKIE_HOST_ONLY_DECLARED:'Domain 없는 호스트 한정 선언',
  COOKIE_DOMAIN_SHARING_INTENT_UNKNOWN:'Domain 공유 목적은 미확인',
  COOKIE_EXPIRY_NOT_SERVER_INVALIDATION:'쿠키 만료 선언 · 서버 세션 무효화 증명 아님',
  SESSION_EXPIRY_UNKNOWN:'서버 세션 만료·저장소 상태 미확인',
  COOKIE_AUTHENTICATION_NOT_PROVEN:'쿠키 기반 인증 성공은 미검증',
  STATE_CHANGE_CALL_OBSERVED:'지원하는 상태 변경 호출 관찰',STATE_CHANGE_NOT_VERIFIED:'업무 상태 변경 미확인',
  EXACT_ORIGIN_REJECTION_DECLARED:'정확한 Origin 불일치 시 종료 조건 선언',
  CSRF_DEFENSE_UNKNOWN:'CSRF 보호 근거 미확인',
  TOKEN_BINDING_AND_FRAMEWORK_PROTECTION_NOT_VERIFIED:'토큰·세션 연결과 프레임워크 보호는 미검증',
  TS_DENO_REGISTRATION_HINT:'Deno 등록 구문 후보로 선택 · 실제 등록은 별도 확인',
  TS_NEXT_ROUTE_EXPORT_HINT:'Next.js 요청 export 후보로 선택',TS_EXPRESS_MODULE_HINT:'Express import 모듈 후보로 선택',
  TS_EDGE_FUNCTION_CONVENTION_HINT:'Edge Function 폴더 규약 후보 · 진입점 확정 아님',
  TS_SERVER_DIRECTIVE_HINT:'서버 지시어 후보로 선택',TS_RELATED_IMPORT_HINT:'서버 후보의 제한된 상대 import 관계',
  TS_SERVER_USE_IMPORT_HINT:'상대 import 연결과 서버 작업 구문 후보 · 실행 근거는 별도 확인',
  TS_NODE_MANIFEST_ENTRY_HINT:'package.json의 시작 파일 단서 · 실행 여부는 미확인',
  TS_PATH_CONFIG_UNKNOWN:'tsconfig 상속·형식·제한으로 별칭 해석 보류',
  TS_PATH_TARGETS_UNSUPPORTED:'단일 정적 경로만 지원 · 복수 대상 등은 미확인',
  TS_PATH_OUTSIDE_INPUT:'입력 프로젝트 밖 별칭은 연결하지 않음',
  TS_PATH_TARGET_AMBIGUOUS:'별칭 대상 파일이 여러 개여서 연결 보류',
  TS_PATH_TARGET_NOT_INSPECTED:'별칭 대상 파일 미수집·미검사',
  TS_STATIC_PATH_ALIAS_LINK:'정적 tsconfig 별칭으로 소스 연결 · 실행·권한 검증 아님',
  NEXT_ACCESS_ASSOCIATION_BUDGET_LIMIT:'요청 선언과 데이터 접근의 연결 예산 부족',
  NODE_PACKAGE_CONFIGURATION_UNKNOWN:'패키지 설정을 해석하지 못해 모듈 연결 보류',
  NODE_MODULE_TARGET_NOT_INSPECTED:'우선 해석 대상 파일이 검사 범위에 없어 연결 보류',
  NODE_REQUIRE_FORMAT_NOT_SUPPORTED:'CommonJS에서 해당 모듈 형식 연결 미지원',
  NODE_ESM_DIRECTORY_OR_TARGET_NOT_SUPPORTED:'ESM 디렉터리 또는 대상 모듈 연결 미지원',
  NODE_MODULE_PATH_OUTSIDE_INPUT:'입력 프로젝트 밖의 모듈 경로는 연결하지 않음',
  NODE_MODULE_SPECIFIER_NOT_SUPPORTED:'동적·특수 모듈 경로 형식 미지원',
  NODE_IMPORT_SOURCE_MAPPING_NOT_RUNTIME_PROOF:'소스 파일 관계 · Node.js 실행 해석을 보증하지 않음',
  NODE_DIRECTORY_INVENTORY_INCOMPLETE:'디렉터리의 패키지 설정·파일 목록을 확인하지 못해 연결 보류',
  NODE_COMMONJS_DIRECTORY_SOURCE_LINK:'CommonJS 상대 디렉터리의 소스 연결 · 실행 여부는 미확인',
  EXPRESS_SETTING_READ_NOT_ROUTE:'Express 설정값 조회 · 요청 등록이나 설정값 확인은 아님',
  TS_SUPABASE_CLIENT_MODULE_HINT:'Supabase SDK import 모듈 후보 · Client 의미 연결의 증명 아님',
  TS_POLICY_SQL_INPUT:'저장소 정책 SQL 입력',TS_DETERMINISTIC_FALLBACK:'일반 코드 예약·남은 예산으로 선택',
  TS_SELECTION_HINT_LIMIT:'파일 선택용 힌트 탐색 상한 · 일부 관계 미확인',
  TS_SELECTION_HINTS_NOT_ENTRY_PROOF:'선택 우선순위는 힌트이며 요청·보안 흐름의 증명이 아님',
  TS_COMBINED_SOURCE_SQL_BUDGET_PARTIAL:'JS/TS·정책 SQL 공통 예산으로 일부 파일 미검사',
  SOURCE_FILE_SIZE_LIMIT:'개별 파일 문자 수 상한',SOURCE_FILE_COUNT_LIMIT:'JS/TS·SQL 공통 파일 수 상한',SOURCE_TOTAL_CHAR_LIMIT:'JS/TS·SQL 공통 문자 수 상한',
  NEXT_ROUTE_HANDLER:'Next.js 요청 처리 함수 선언',NEXT_SERVER_FUNCTION:'Next.js 서버 함수 선언 · 호출 여부 미확인',
  SERVER_FUNCTION_ARGUMENT:'외부에서 전달할 수 있는 서버 함수 인자',SERVER_FUNCTION_RETURN:'서버 함수 반환 위치',
  NEXT_SERVER_FUNCTION_INVOCATION_NOT_VERIFIED:'서버 함수의 실제 호출·배포 여부는 미확인',
  NEXT_AUTHENTICATION_IS_NOT_RESOURCE_AUTHORIZATION:'로그인 확인과 개별 데이터 접근권한은 별도 검토 필요',
  NEXT_ROUTING_CONFIG_AND_MIDDLEWARE_NOT_VERIFIED:'기본 App Router 규약만 대조 · 라우팅 설정·미들웨어는 미검증',
  NEXT_ROUTE_AUTHORIZATION_NOT_VERIFIED:'요청별 인증·소유권 검사는 미확인',
  NEXT_INLINE_SERVER_CLOSURE_NOT_SUPPORTED:'중첩 서버 함수의 클로저·호출 관계는 미지원',
  NEXT_PAGES_API_NOT_SUPPORTED:'Pages Router API 요청 흐름은 이번 분석 범위 밖',
  NEXT_CLIENT_BOUNDARY_BUNDLE_NOT_VERIFIED:'클라이언트 경계 선언 확인 · 실제 브라우저 번들은 미검증',
  NEXT_SERVER_ONLY_DECLARATION_NOT_RUNTIME_PROOF:'서버 전용 모듈 선언 · 실제 빌드 경계는 미검증',
  NEXT_CONFLICTING_SERVER_CLIENT_DIRECTIVES:'서버·클라이언트 선언이 충돌해 경계 미확인',
  NEXT_VERSION_CONTRACT_NOT_SUPPORTED:'Next.js 선언 버전의 요청 규약은 미지원',
  NEXT_SERVER_FUNCTION_CONTRACT_NOT_SUPPORTED:'서버 함수 버전·async 규약을 확인하지 못함',
  NEXT_REEXPORT_REGISTRATION_NOT_SUPPORTED:'재수출한 요청·서버 함수 등록은 미지원',
  NEXT_MUTABLE_EXPORT_NOT_SUPPORTED:'변경되는 export의 실제 요청 대상을 확인하지 못함',
  NEXT_REGISTRATION_BUDGET_EXCEEDED:'Next.js 경계 확인 중 분석 예산 상한 도달',
  DENO_HTTP_HANDLER:'Deno HTTP 요청 등록 확인',
  REQUEST_SELECTED_ENVIRONMENT_VALUE:'요청으로 선택한 서버 환경값',
  SERVER_SECRET_ENVIRONMENT_VALUE:'서버 비밀 설정 참조 · 실제 값은 수집하지 않음',
  DECLARED_PUBLIC_ENVIRONMENT_VALUE:'공개용으로 선언된 환경 설정',
  SUPABASE_VERIFY_JWT_DECLARED_TRUE:'JWT 검증 활성화 선언 · 실제 배포 상태는 미확인',
  SUPABASE_VERIFY_JWT_DECLARED_FALSE:'JWT 검증 비활성화 선언 · 별도 보호 로직 확인 필요',
  SUPABASE_VERIFY_JWT_DECLARATION_UNKNOWN:'함수별 JWT 검증 설정을 확인하지 못함',
  SUPABASE_LIVE_AUTHORIZATION_AND_RLS_NOT_VERIFIED:'운영 인증·사용자 권한·RLS 적용 상태는 미검증',
  AUTHORIZATION_AND_DEPLOYMENT_NOT_VERIFIED:'접근권한과 실제 배포 조건은 미확인',
  ENVIRONMENT_CONTENTS_AND_GATEWAY_POLICY_UNKNOWN:'환경값의 실제 내용과 게이트웨이 정책은 미확인',
  BRANCH_FEASIBILITY_NOT_VERIFIED:'해당 분기의 실제 실행 가능성은 미검증',
  CONTEXT_MISSING:'연결에 필요한 로컬 소스 문맥 누락',FRAMEWORK_NOT_SUPPORTED:'이 프레임워크의 요청 등록 계약은 미지원',
  EXTERNAL_IMPLEMENTATION_UNKNOWN:'외부 구현 또는 등록 관계 미확인',CALL_TARGET_UNKNOWN:'콜백 대상을 확인하지 못함',
  ANALYSIS_STEP_BUDGET_EXCEEDED:'구문·값 전달 분석 작업량 상한 도달',ANALYSIS_TIME_BUDGET_EXCEEDED:'분석 시간 상한 도달',
  NODE_DISCOVERY_IMPORT_DEPTH_LIMIT:'상위 모듈 탐색 깊이 상한',ENTRY_CONTRACT_ANALYSIS_INCOMPLETE:'등록 계약 분석 일부 미완료',
  PASSPORT_DECLARATION_NOT_HTTP_ENTRY:'Passport 등록 선언만 확인 · HTTP 요청 진입점 확정은 아님',
  PASSPORT_STRATEGY_REGISTRATION:'Passport 전략 등록 위치',PASSPORT_VERIFY_CALLBACK:'토큰 확인 콜백 위치',
  PASSPORT_AUTHENTICATOR_REFERENCE:'인증 middleware 참조 위치',ROUTER_FACTORY_TARGET:'Router 반환 함수',
  STATIC_CALL_ONLY_NOT_RUNTIME_PROOF:'정적 호출 연결이며 실제 서버 실행을 입증하지 않음',STATIC_REGISTRATION_ONLY:'정적 요청 등록 근거',
  REGISTRATION_DECLARATION_NOT_HTTP_ENTRY:'등록 선언은 HTTP 진입점이나 취약점의 증명이 아님',
  INITIALIZATION_AND_REQUEST_DISPATCH_NOT_VERIFIED:'초기화 실행과 실제 요청 전달은 미확인',
  PASSPORT_LIBRARY_VERSION_NOT_VERIFIED:'실제 Passport 설치 버전·구현은 미검증',
  SAME_FILE_REGISTRATION_SCOPE_ONLY:'같은 파일의 명시적 등록만 대조함',NOT_AUTHORIZATION_OR_SIGNATURE_PROOF:'접근권한·토큰 서명 검증의 증명은 아님',
  EXPRESS_QUERY:'요청 검색값',EXPRESS_BODY:'요청 본문',EXPRESS_PARAMS:'요청 경로값',EXPRESS_REGISTRATION:'정적 Express 요청 연결',
  PRINCIPAL_CONTEXT_UNVERIFIED:'요청 사용자·세션 참조 · 인증·권한 검증의 증명은 아님',EVAL_CALL:'서버 코드 실행 호출',
  FUNCTION_RETURN:'함수 반환으로 전달',NODE_FLOW_UNRESOLVED:'Node.js 값 전달 또는 제어 흐름 미확인',
  MONGODB_RECEIVER_OR_OBJECT_FLOW_UNRESOLVED:'MongoDB 객체 출처 또는 객체 전달을 확인하지 못함',
  NODE_EXEC_SHELL:'Node.js shell 명령 호출',NODE_EXECSYNC_SHELL:'Node.js 동기 shell 명령 호출',NODE_PROCESS_ARGUMENTS:'프로세스 인자 전달 위치',
  SEQUELIZE_RAW_QUERY:'Sequelize SQL 실행 위치',SEQUELIZE_DECLARED_INSTANCE_ORIGIN:'선언된 Sequelize 인스턴스 생성 위치',
  SEQUELIZE_REGISTRY_SUMMARY:'제한된 모델 초기화 근거',SEQUELIZE_STATIC_MODEL_INVENTORY:'정적 소스 목록의 모델 등록 구조',SEQUELIZE_DEFINE_ONLY_MODEL:'선언만 확인한 모델',
  SEQUELIZE_INITIALIZATION_SUMMARY_NOT_RUNTIME_EXECUTION:'제한된 초기화 요약 · 실제 초기화 실행 아님',
  SEQUELIZE_DECLARED_API_VERSION_UNKNOWN:'지원하는 Sequelize 선언 버전을 확인하지 못함',SEQUELIZE_CONSTRUCTOR_EFFECTS_UNKNOWN:'Sequelize 생성자 옵션의 부작용 미확인',
  SEQUELIZE_QUERY_ARGUMENT_CONTRACT_UNKNOWN:'Sequelize 쿼리 인자 계약 미확인',SOURCE_INVENTORY_NOT_RUNTIME_DIRECTORY:'수집된 소스 목록 기준 · 운영 디렉터리는 미확인',
  SEQUELIZE_IMPORT_API_UNSUPPORTED:'선언된 버전에서 모델 import 초기화 계약 미지원',SEQUELIZE_MODEL_INVENTORY_INCOMPLETE:'모델 파일 목록이 불완전해 초기화 출처를 확정하지 않음',
  SEQUELIZE_MODEL_NOT_PARSED_OR_UNSUPPORTED:'모델 파일 미검사 또는 선언 외 부작용 미지원',
  DECLARED_VERSION_NOT_INSTALLED_VERSION:'선언 버전 기준 · 실제 설치 버전은 미확인',MODEL_API_AND_AUTHORIZATION_NOT_PROVEN:'모델 API 및 접근권한은 검증하지 않음',
  NODE_PROCESS_API_ORIGIN_UNKNOWN:'프로세스 API가 변경되어 실제 호출 대상을 확인하지 못함',NODE_PROCESS_OPTIONS_UNVERIFIED:'프로세스 호출 옵션의 의미 미확인',
  NODE_PROCESS_ARGV_NOT_WHOLE_OPERATION_SAFETY:'shell 미사용 기본 계약 관찰 · 실행 파일·인자·플랫폼 전체 안전 미검증',
  NODE_PROCESS_ARGV_AND_OPTIONS_NOT_MODELED:'프로세스 인자·shell 옵션 문맥 미지원',EXECUTABLE_ARGUMENT_INJECTION_AND_PLATFORM_NOT_VERIFIED:'실행 파일 선택·인자 주입·플랫폼 동작 미검증',
  ARGV_WITHOUT_SHELL_DECLARED:'고정 실행 파일·인자 배열의 shell 미사용 기본 계약 관찰',PROCESS_CONTRACT_UNKNOWN:'프로세스 실행 계약 미확인',
  STATIC_PATH_NOT_RUNTIME_EXPLOIT_PROOF:'정적 경로이며 실제 공격 성공은 미검증',
  MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED:'미들웨어의 입력 검증과 실제 실행 환경은 미확인',
  MULTI_REQUEST_GLOBAL_LIFECYCLE_NOT_VERIFIED:'각 요청은 초기화 상태에서 따로 검사합니다. 여러 요청 사이의 전역 상태 변화는 미검증입니다.',
  OBJECT_OWNERSHIP_AND_MIDDLEWARE_NOT_VERIFIED:'객체 소유권과 미들웨어 보호는 미확인',
  INTERNAL_ERROR_DETAIL:'내부 오류 스택 정보',ERROR_DETAIL_CONTEXT_UNKNOWN:'오류 스택 문맥 미확인',HTTP_CLIENT_CALL:'외부 HTTP 호출',
  HTTP_LIBRARY_VERSION_AND_PATCHES_UNVERIFIED:'HTTP 라이브러리·버전·변경 여부 미확인',PROXY_PLATFORM_AND_TOTAL_DEADLINE_UNKNOWN:'프록시·플랫폼 제한·전체 요청 기한 미확인',STATIC_CALL_NOT_SERVICE_FAILURE_PROOF:'정적 호출 근거이며 운영 장애를 확인한 것은 아님',
  CREDENTIAL_SHAPED_LITERAL:'자격증명 형식의 고정 값 · 원문은 저장하지 않음', FRAMEWORK_SECRET_SETTING:'Django 서버 비밀 설정 참조',
  AUTHENTICATION_HEADER:'인증·쿠키 헤더', ENVIRONMENT_VALUE_UNVERIFIED:'환경 설정 참조 · 실제 민감성 미확인', HTTP_RESPONSE:'응답 생성 위치',
  HTTP_RESPONSE_RETURN:'서버 응답 반환', EXPRESS_HTTP_RESPONSE:'Express 응답 전송 호출', HTTP_RESPONSE_SEND:'Express 응답 전송', LOG_ARGUMENT:'로그 인자 전달', STATIC_EXPOSURE_NOT_RUNTIME_LEAK_PROOF:'정적 전달 근거이며 실제 유출은 미검증',
  EXPRESS_RESPONSE_SERIALIZATION_AND_MIDDLEWARE_NOT_VERIFIED:'실제 응답 변환·직렬화 설정·공통 미들웨어는 미검증',
  EXPRESS_RESPONSE_ARGUMENT_CONTRACT_UNKNOWN:'여러 응답 인자의 역할을 확인하지 못함',
  EXPRESS_JSON_REPLACER_CONTEXT_UNVERIFIED:'JSON 변환 설정 후보가 있어 기본 응답 직렬화를 가정하지 않음 · 실제 적용 앱은 미확인',
  EXPRESS_RESPONSE_RENDER_OR_REDIRECT_NOT_MODELED:'템플릿 응답·리다이렉트의 전달 의미는 미지원',
  SERVER_ENVIRONMENT_PROVENANCE_UNVERIFIED:'환경 객체의 별칭·변경·외부 전달 때문에 실제 출처를 확인하지 못함',
  MASKING_LOG_ACCESS_AND_DEPLOYMENT_UNKNOWN:'외부 마스킹·로그 접근·배포 실행 문맥 미확인',
  TOKEN_API_CALL: 'JWT API 호출', TOKEN_SECURITY_USE: '토큰의 보안 사용 위치', TOKEN_CLAIM_DECISION: '토큰 값으로 접근 조건 판단',
  TOKEN_TRANSFORM_OR_EXTERNAL_VALIDATION_UNKNOWN: '다른 함수의 토큰 변환·검증 효과 미확인',
  TOKEN_VALUE_OR_EXECUTION_UNRESOLVED: '토큰 값 전달 또는 실행 경로 일부 미확인',
  TOKEN_CALLS_OUTSIDE_TRACED_FLOW: '구문에서 발견한 JWT API 후보 중 추적하지 못한 호출이 있음',
  PYJWT_2_API_SHAPE_LIBRARY_VERSION_NOT_VERIFIED: 'PyJWT 2.x API 형태 · 실제 설치 라이브러리·버전 미확인',
  EXTERNAL_TOKEN_VALIDATION_NOT_VERIFIED: '다른 계층의 토큰 검증 미확인',
  AUTH_LOGIC_CANDIDATE_NOT_EXPLOIT_PROOF: '비교·차단 로직의 검토 후보이며 실제 권한 우회 성공은 미검증',
  AUTH_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED: '외부 미들웨어·실행 환경의 추가 보호는 미확인',
  RESOURCE_LOOKUP: '요청 식별자로 리소스 조회', INVERTED_OWNER_REJECTION: '소유자 일치 시 차단하는 분기',
  RESOURCE_WRITE: '리소스 저장 호출', RESOURCE_DELETE: '리소스 삭제 호출',
  UPLOADED_FILE: '업로드된 파일 데이터', PATH_CONSTRUCTION: '파일 경로 구성', PATH_NORMALIZATION: '경로 정규화 · 디렉터리 제한 증거는 아님',
  FILE_ACCESS_CALL: '파일 접근 호출', DESERIALIZATION_CALL: '데이터 복원 호출',
  INPUT_IN_FILE_PATH: '요청 값이 파일 경로에 전달됨', INPUT_TO_UNSAFE_DESERIALIZATION: '요청 데이터가 위험한 복원 호출에 전달됨',
  LEXICALLY_CONFINED_PATH: '고정 기준 디렉터리와 safe_join의 문자열 경계 제한 확인',
  SAFE_PARSER_DECLARATION: 'JSON 또는 안전 로더 호출 형태 확인 · 다른 위험까지 보증하지 않음',
  FIXED_SOURCE_NO_REQUEST_FLOW: '고정 값에서 호출 · 요청 입력 전달은 확인되지 않음', UNRESOLVED_RESOURCE: '파일·데이터 출처 또는 처리 과정 미확인',
  RESOURCE_FLOW_UNRESOLVED: '입력 전달·변환·실행 조건 중 일부를 확인하지 못함',
  RESOURCE_CALLS_OUTSIDE_TRACED_FLOW: '구문에서 발견한 파일·복원 API 후보 중 추적하지 못한 호출이 있음',
  DJANGO_SAFE_JOIN_LITERAL_BASE: '고정 기준 디렉터리의 Django safe_join 확인',
  SYMLINKS_PERMISSIONS_AND_RUNTIME_NOT_VERIFIED: '심볼릭 링크·파일시스템 상태·접근 권한·운영 실행은 미검증',
  LIBRARY_VERSION_AND_EXPLOITABILITY_NOT_VERIFIED: '라이브러리 버전별 동작과 실제 공격 가능성은 미검증',
  BOUNDED_PYTHON_FILE_AND_DESERIALIZATION_ONLY: 'Python의 지원 파일 API·pickle·YAML 호출만 제한적으로 추적',
  MODULE_OBJECT_WRITE_UNRESOLVED: '모듈 객체 변경으로 호출 대상의 원래 동작을 확인하지 못함',
  LAZY_DESERIALIZATION_EXECUTION_NOT_VERIFIED: '지연 복원 결과의 실제 순회·실행 여부는 확인하지 못함',
  UNSUPPORTED_ARGUMENT_TYPE: '요청 문자열은 이 복원 API가 요구하는 바이트 형식과 다름 · 취약점으로 연결하지 않음',
  PICKLE_LOADS_REQUIRES_BYTES_NOT_REQUEST_TEXT: 'pickle.loads는 바이트 입력을 요구합니다. 확인한 문자열 흐름을 실행 가능한 복원 위험으로 계산하지 않았습니다.',
  COMPLETE: '제한된 범위 확인 완료', PARTIAL: '일부만 확인', NOT_APPLICABLE: '대상 파일 없음',
  UNAVAILABLE: '분석하지 못함', TIMEOUT: '분석 시간 초과', DISABLED: '실행하지 않음',
  PARSED: '구문 확인', PARSE_FAILED: '구문 파싱 실패', LIMIT_EXCEEDED: '크기·자원 제한', NOT_RUN: '미실행',
  SUPPORTED_FLOW_ANALYZED: '지원하는 값 전달 경로 확인', NOT_SUPPORTED: '지원되는 서버 흐름 아님',
  INPUT_IN_QUERY: '요청 값이 쿼리 문자열에 포함', PARAMETERIZED_QUERY: '정적 쿼리와 값 바인딩 확인',
  STATIC_QUERY: '정적인 쿼리 구성 확인', UNRESOLVED_QUERY: '쿼리 구성 확인 불가',
  QUERY_PARAMETER: 'URL에서 받은 값', REQUEST_BODY: '요청 본문', ROUTE_PARAMETER: '경로에서 받은 값',
  REQUEST_URL: '요청 URL', VARIABLE: '변수로 전달', ASSIGNMENT: '변수에 대입', FUNCTION_ARGUMENT: '함수 인자로 전달',
  REGEX_CAPTURE: '일치한 입력에서 캡처한 값 · 안전한 검증을 의미하지 않음',
  REGEX_CAPTURE_UNVERIFIED: '캡처 값 또는 일치 성공 여부를 확인하지 못함',
  REGEX_MATCH_CONTRACT_UNKNOWN: '정규식·입력·호출 계약을 확인하지 못함',
  REGEX_SYNTAX_OR_RESOURCE_UNSUPPORTED: '정규식 구문 또는 분석 한도 밖',
  EXTERNAL_PROPERTY_WRITE_SCOPED_UNKNOWN: '미확인 외부 객체의 속성 변경 · 해당 객체의 동작 미검증',
  RESTRICTED_SHELL_TOKEN: '허용 문자로 제한된 명령 인자 · 실행 환경 안전성은 별도 확인',
  D1_PREPARE: '데이터베이스 쿼리 구성', VALUE_BINDING: '값 매개변수 바인딩',
  SQL_STRING_CONSTRUCTION: '문자열 구성 · 실제 사용 위치는 전달 근거 참조', SQL_EXECUTION_CALL: '쿼리 실행 호출',
  LITERAL_IDENTIFIER_ALLOWLIST: '고정된 식별자 허용 목록과 분기 확인',
  SCHEDULED_ENTRY_NOT_SUPPORTED: '예약 실행 진입점은 현재 추적 대상이 아님',
  LOGIN_CONTEXT_REFERENCE: '로그인 문맥 참조', CONDITIONAL_CHECK: '조건 분기',
  EARLY_EXIT_BRANCH_PRESENT: '처리를 중단하는 분기', NUMERIC_CONVERSION: '숫자 변환',
  VALIDATION_EXPRESSION_PRESENT: '입력 검사 표현식',
  CALL_DEPTH_EXCEEDED: '함수 추적 깊이 또는 순환 호출 제한', CALL_TARGET_UNRESOLVED: '호출 대상이나 처리 내용 확인 불가',
  STRING_FORMAT_UNRESOLVED: '문자열 포맷이 동적이거나 지원 범위를 벗어나 실제 사용되는 값을 확인하지 못함',
  LOOP_FLOW_PARTIAL: '반복문 전체 경로 미검증', EXCEPTION_FLOW_PARTIAL: '예외 처리 전체 경로 미검증',
  SWITCH_FLOW_PARTIAL: '분기 간 전체 경로 미검증', CALLBACK_FLOW_UNSUPPORTED: '콜백 내부 값 전달 미지원',
  UNREACHED_FUNCTIONS_NOT_ANALYZED: '진입점에서 연결하지 못한 함수는 미검사',
  NO_SUPPORTED_SERVER_ENTRY_OR_CALL: '지원하는 서버 진입점 또는 함수 호출을 확인하지 못함',
  REACT_UI_NOT_SERVER_AUTHORIZATION: 'React 화면의 제한을 서버 권한 검사로 취급하지 않음',
  SOURCE_LIMIT_EXCEEDED: '파일 크기·개수·전체 텍스트 제한', ANALYSIS_BUDGET_EXCEEDED: '시간·작업량 제한',
  INVALID_SYNTAX: '지원 파서에서 구문을 읽지 못함', QUERY_HAS_UNRESOLVED_VALUES: '쿼리 값의 일부 처리 과정 미확인',
  QUERY_CONSTRUCTION_NOT_EXPLOIT_PROOF: '쿼리 구성 근거이며 실제 공격 성공을 확인한 것은 아님',
  BIND_DOES_NOT_REWRITE_QUERY: '바인딩도 있지만 이미 결합된 쿼리 문자열은 바꾸지 않음',
  PATH_FEASIBILITY_NOT_VERIFIED: '실행 조건과 실제 공격 가능성은 별도 확인 필요',
  EXECUTION_PATH_PARTIAL: '실행 호출 주변의 제어 흐름을 일부만 확인함',
  TRACE_DETAILS_TRUNCATED: '전달 경로가 길어 일부 중간 단계를 생략함',
  PREPARE_CALLS_OUTSIDE_TRACED_FLOW: 'prepare 호출 구문 중 확인한 서버 경로에 연결되지 않은 부분이 있음',
  REQUEST_HEADER: '요청 헤더에서 받은 값', HTTP_REQUEST_CALL: '서버 HTTP 요청 호출', URL_STRING_CONSTRUCTION: '요청 주소 문자열 구성',
  INPUT_IN_DESTINATION: '외부 입력이 요청 목적지를 결정할 수 있음', FIXED_DESTINATION: '초기 목적지는 고정됨',
  ALLOWLISTED_DESTINATION: '파싱한 프로토콜·호스트의 정확한 허용 목록 확인', UNRESOLVED_DESTINATION: '목적지 결정 과정 확인 불가',
  PARSED_URL_ALLOWLIST: '파싱한 URL 속성의 정확한 허용 목록',
  DESTINATION_FLOW_UNRESOLVED: 'URL 변환·방어·실행 경로 일부 미확인', URL_MUTATION_UNRESOLVED: 'URL 속성 변경을 완전히 추적하지 못함',
  REDIRECT_DNS_REACHABILITY_NOT_VERIFIED: '리다이렉트·DNS 재해석·실제 네트워크 접근 가능성 미검증',
  PORT_POLICY_NOT_VERIFIED: '허용 목록의 포트 정책은 별도 확인 필요',
  URL_PROPERTY_WRITE: 'URL 속성 대입 확인·함수 간 변경은 제한적으로 추적', URL_QUERY_WRITE: '검색값 변경 확인·함수 간 변경은 제한적으로 추적',
  HEADER_MUTATION_PARTIAL: '요청 헤더 변경 후의 값을 완전히 추적하지 못함',
  HTTP_CALLS_OUTSIDE_TRACED_FLOW: 'fetch 구문 중 확인한 서버 경로에 연결되지 않은 부분이 있음',
  WHOLE_URL: '전체 주소', HOST_OR_AUTHORITY: '호스트 또는 주소 권한부', WHOLE_URL_OR_HOST: '전체 주소 또는 호스트',
  PATH_QUERY_OR_NONE: '경로·검색값 또는 입력 영향 없음', UNKNOWN: '확인 불가',
  SERVER_ENTRY: '서버 요청 진입점', AUTH_DECLARATION: '인증·권한 설정 선언',
  BOUNDED_DJANGO_DRF_ONLY: 'Django/DRF의 일부 진입점과 지원되는 값 전달만 검사',
  MIDDLEWARE_SETTINGS_AND_OWNERSHIP_NOT_VERIFIED: '미들웨어·전역 설정·리소스 소유권은 미검증',
  STATIC_FLOW_NOT_EXPLOIT_PROOF: '정적 전달 경로이며 공격 성공을 확인한 것은 아님',
  NO_OS_SANDBOX: '시간·입출력 제한 프로세스이며 OS 수준 완전 격리는 아님',
  RSS_CHECK_NOT_HARD_MEMORY_LIMIT: '이 환경은 메모리 사용량 점검이며 OS 강제 메모리 제한은 아님',
  SQL_CALLS_OUTSIDE_TRACED_FLOW: '확인한 서버 경로 밖에도 SQL 호출 후보 구문이 있음',
  LAZY_RAW_EXECUTION_NOT_VERIFIED: 'raw 쿼리의 지연 실행 시점 미확인',
  ROUTE_TARGET_UNRESOLVED: 'URL 경로의 요청 처리 함수를 확인하지 못함',
  AST_NODE_LIMIT: '구문 트리 크기 제한', RESULT_LIMIT_EXCEEDED: '기록 가능한 근거 수 제한',
  ASYNC_EXECUTION_UNRESOLVED: '비동기 호출 실행 흐름 미확인',
  MUTABLE_OBJECT_WRITE_UNRESOLVED: '객체 변경과 별칭의 영향을 확인하지 못함',
  CONTEXT_MANAGER_UNRESOLVED: '컨텍스트 관리자의 실행 흐름 미확인',
  ORM_VALUE_QUERY: 'ORM 값 매개변수 호출 형태 확인', ORM_VALUE_PARAMETERS: 'ORM의 값 매개변수 사용',
  NUMERIC_ROUTE_CONVERTER: '정수형 경로 변환 선언', ROUTE_PARAMETERS_UNRESOLVED: '경로 인자의 전달 방식 미확인',
  DECORATOR_EXECUTION_UNRESOLVED: '사용자 정의 데코레이터의 실행 영향 미확인',
  CUSTOM_MANAGER_AND_RUNTIME_NOT_VERIFIED: '사용자 정의 Manager와 실제 실행 환경은 미검증',
  INPUT_GUARD_UNRESOLVED: '입력에 대한 사용자 정의 검증 함수의 효과 미확인',
  FILE_COUNT_LIMIT: '분석할 파일 수 상한으로 선택하지 못함',
  FILE_CHARACTER_LIMIT: '이 파일의 문자 수 상한 초과',
  TOTAL_CHARACTER_LIMIT: '전체 소스 문자 수 상한으로 선택하지 못함',
  DJANGO_ROUTING_HINT: 'Django 경로 설정 후보를 우선 선택',
  DJANGO_ENTRY_HINT: 'Django/DRF 요청 처리 선언 후보를 우선 선택',
  DJANGO_SETTINGS_REFERENCE_HINT: 'Django 설정 모듈 참조 후보를 우선 선택',
  RELATED_IMPORT_HINT: '요청 경로 후보와 연결된 정적 import 참조',
  DETERMINISTIC_FALLBACK: '연결 근거 밖의 나머지 파일을 경로순 선택',
  SELECTION_HINT_LIMIT: '파일 선택용 사전 조사 상한으로 연결 관계를 일부 확인하지 못함',
  LEXICAL_SELECTION_HINTS_NOT_VERIFIED_ENTRIES: '파일 선택 단서는 우선순위용이며 실제 진입점은 구문 분석으로 별도 확인',
  SOURCE_LIMITS_OR_SENSITIVE_PATHS_OMITTED: '소스 제한 또는 민감한 경로로 선택하지 못한 파일이 있음',
  OMITTED_FILE_DETAILS_TRUNCATED: '미선택 파일 기록 일부를 생략함. 표시 파일 수는 전체 파일 수가 아님',
  CALL_ARGUMENT_BINDING_UNRESOLVED: '함수 인자를 올바르게 전달할 수 있는지 확인하지 못함',
  UNPACKING_UNRESOLVED: '묶음 값의 개별 변수 전달을 확인하지 못함',
};
const text = (value: string) => labels[value] ?? (/^[A-Z_]+$/.test(value) ? '지원 범위 밖이거나 추가 확인이 필요한 처리' : value);
const location = (value: AnalysisLocation) => `${value.filePath}:${value.line} · ${value.functionName}`;

export function ServerAnalysisSection({ snapshot, compact = false, onEditFile }: { snapshot?: ServerAnalysisSnapshot | null; compact?: boolean; onEditFile?: (path: string) => void }) {
  return <>
    <SupabaseAnalysisSection snapshot={snapshot?.supabaseAnalysis} compact={compact} />
    <JavaSqlAnalysisSection snapshot={snapshot?.javaAnalysis} compact={compact} />
    <DeploymentAnalysisSection snapshot={snapshot?.deploymentAnalysis} compact={compact} />
    <LanguageAnalysisSection snapshot={snapshot} compact={compact} onEditFile={onEditFile} />
    {snapshot?.pythonAnalysis && snapshot.pythonAnalysis.status !== 'NOT_APPLICABLE' &&
      <LanguageAnalysisSection snapshot={snapshot.pythonAnalysis} compact={compact} python onEditFile={onEditFile} />}
  </>;
}

function LanguageAnalysisSection({ snapshot, compact = false, python = false, onEditFile }: { snapshot?: ServerAnalysisSnapshot | null; compact?: boolean; python?: boolean; onEditFile?: (path: string) => void }) {
  const [page, setPage] = useState(0);
  if (!snapshot) return compact ? null : <section className="analysis-coverage-brief"><h3>서버 코드 흐름 검사</h3>
    <p>이 이력에는 서버 코드 흐름 기록이 없습니다. 과거 분석을 추측하여 채우지 않습니다.</p></section>;
  const validated = snapshot.validatedFindings ?? [];
  const candidates = snapshot.findings.filter(candidate => !validated.some(f => f.evidence.some(e => JSON.stringify(e) === JSON.stringify(candidate))));
  const title = python ? 'Python 서버 코드 흐름 검사' : '서버 코드 흐름 검사';
  if (compact) return <section className="analysis-coverage-brief" aria-label={python ? 'Python 서버 코드 흐름 요약' : '서버 코드 흐름 요약'}><h3>{title}</h3>
    <p>{text(snapshot.status)} · {snapshot.validatedFindings == null ? '실행 경로 Finding 연결 미기록' : `정적 근거가 연결된 검토 항목 ${validated.length}건`} · 추가 문맥 확인 {candidates.length}건</p>
    {python && <PythonCoverageSummary snapshot={snapshot} />}
    <p>기존 배포 판단과 점수에 합산하지 않은 별도 결과입니다. ‘배포 전 직접 확인’에서 근거와 검사하지 못한 부분을 확인하세요.</p></section>;
  const current = Math.min(page, Math.max(0, Math.ceil(snapshot.files.length / 10) - 1));
  return <section className="server-analysis-section" aria-label={title}>
    <h3>{title}</h3><p>{text(snapshot.status)}</p>
    {!python&&['ts-server-v11','ts-server-v12','ts-server-v13','ts-server-v14','ts-server-v15','ts-server-v16'].includes(snapshot.analyzerVersion)&&snapshot.nodeUses!=null&&<p className="review-caution">
      소스 기록 {snapshot.files.length}개 · 파싱 {snapshot.files.filter(f=>f.parseStatus==='PARSED').length}개 ·
      요청 등록 {snapshot.nodeUses.filter(u=>u.kind==='ENTRY_REGISTERED').length}곳 ·
      Router 반환 연결 {snapshot.nodeUses.filter(u=>u.kind==='CALL_LINKED').length}곳 ·
      분석 제한 기록 {snapshot.files.filter(f=>f.limitations.some(l=>l.includes('BUDGET_EXCEEDED')||l.includes('DEPTH_LIMIT'))).length}개 파일.
      파싱·등록·호출 연결은 전체 보안 흐름 검증이나 안전 판정이 아닙니다.
    </p>}
    {!python&&snapshot.selectionCoverage&&<p className="review-caution">
      JS/TS·정책 SQL 후보 {snapshot.selectionCoverage.discoveredFiles}개 · 분석 입력 선택 {snapshot.selectionCoverage.submittedFiles}개 ·
      미선택 {snapshot.selectionCoverage.omittedFiles}개 · 선택한 문자 {snapshot.selectionCoverage.submittedCharacters}자.
      입력 선택은 구문 파싱이나 보안 흐름 검증 완료가 아닙니다. 미선택 파일은 안전으로 처리하지 않습니다.
    </p>}
    {!python&&snapshot.files.some(f=>f.limitations.some(l=>l.startsWith('NEXT_')))&&<p className="review-caution">
      Next.js 요청 함수 {snapshot.authorizationContexts.filter(c=>c.entry.kind==='NEXT_ROUTE_HANDLER').length}곳 ·
      서버 함수 선언 {snapshot.authorizationContexts.filter(c=>c.entry.kind==='NEXT_SERVER_FUNCTION').length}곳.
      서버 함수 선언은 실제 호출·인증·데이터 접근권한의 증명이 아닙니다. 서버 내부에서 사용하는 설정과 반환값으로 전달되는 설정을 구분하며, 실제 클라이언트 번들은 검사하지 않았습니다.
    </p>}
    {python && <p>Django/DRF에서 연결된 일부 요청 경로의 SQL·파일 경로·pickle/YAML 값 전달을 확인한 결과입니다. 전체 Python 코드·인증·권한·미들웨어를 검사한 것은 아닙니다.</p>}
    {python && <PythonCoverageSummary snapshot={snapshot} />}
    <p className="review-caution">코드 구조에서 확인한 별도 검토 항목입니다. 기존 점수·위험 판정·반드시 처리 건수에 합산하지 않습니다. 항목이 없어도 전체 코드가 안전하다는 의미는 아닙니다.</p>
    {snapshot.findings.length === 0 && <p>지원 범위에서 보고된 요청 값 전달 위험 항목은 없습니다. 미검사·미지원 범위를 함께 확인하세요.</p>}
    <div className="vulnerability-list">{validated.map(finding => <article className="vulnerability-item action-finding" key={finding.findingId}>
      <span className="risk-badge risk-review_required">코드 흐름 · 추가 확인 필요</span>
      <h4>{finding.title}</h4>
      <p className="finding-location"><strong>확인할 파일</strong> {location(finding.location)}</p>
      <p className="finding-next-step">{finding.riskExplanation}</p>
      {onEditFile && <button type="button" className="secondary-button" onClick={() => onEditFile(finding.location.filePath)}>이 파일 수정하기</button>}
      <p className="fix-availability">수동 검토 필요 · 자동/AI 수정은 현재 소스와 지원 조건을 별도로 확인합니다.</p>
      <details className="flow-action-details"><summary>입력 경로와 수정 방법</summary>
      <h4>어떤 입력인가요?</h4>
      {finding.evidence.map((e, i) => <ol className="evidence-path" key={i} aria-label="기록된 코드 전달 경로">{e.flow.map((step,j)=><li key={j}><span>{text(step.kind)}</span><code>{location(step)}</code></li>)}</ol>)}
      <h4>어떻게 수정하나요?</h4><p>{finding.recommendedAction}</p>
      <p>정적 근거 기반 수정 방향입니다. 저장된 AI 해결 가이드 연결은 미기록이며, 실제 코드 변경은 수행하지 않았습니다.</p>
      <h4>수정 후 확인</h4><ol>{finding.verificationSteps.map(step => <li key={step}>{step}</li>)}</ol>
      </details>
      <details className="technical-details"><summary>Finding 기술 근거와 한계</summary>
        <p className="finding-location">{finding.findingId}</p><p>{finding.sourceType} · {finding.ruleId} · {finding.priority} · {finding.analyzerVersion}</p>
        <p>입력 전달과 실행 호출 구문을 확인한 것이며 실제 실행·공격 성공은 검증하지 않았습니다.</p>
        {finding.evidence.map((e, i) => <FlowEvidence key={i} finding={e} />)}
        <ul>{finding.executionLocations.map((entry, i) => <li key={i}>{text(entry.kind)} · <code className="finding-location">{location(entry)}</code></li>)}</ul>
        <p>비교 정책: {finding.comparisonPolicy}. 분석기 버전 변경이나 항목 미표시를 기존 문제의 해결로 계산하지 않습니다.</p>
      </details>
    </article>)}</div>
    {candidates.length > 0 && <h4>추가 문맥이 필요한 후보</h4>}
    <div className="vulnerability-list">{candidates.map((finding, i) => <article className="vulnerability-item action-finding" key={i}>
      <span className="risk-badge risk-review_required">코드 흐름 · 추가 확인 필요</span>
      <h4>{finding.ruleId === 'TS_SSRF_INPUT_FLOW' ? '서버 요청 주소의 처리 과정을 확인해 주세요'
        : finding.ruleId === 'JS_RATE_LIMIT_BYPASS_REVIEW' ? '요청 제한을 건너뛰는 설정과 서버 작업을 확인해 주세요'
        : finding.ruleId === 'JS_CORS_CREDENTIAL_REFLECTION' ? '응답에 적용된 CORS 출처 설정을 확인해 주세요'
        : finding.ruleId === 'JS_SESSION_COOKIE_ATTRIBUTE_REVIEW' ? '세션 쿠키 속성과 실제 발급을 확인해 주세요'
        : finding.ruleId === 'JS_EVAL_INPUT_FLOW' ? '입력값을 코드로 실행하는지 확인해 주세요'
        : finding.ruleId === 'JS_SHELL_COMMAND_INPUT_FLOW' ? '입력값이 서버의 명령 문자열에 전달되는지 확인해 주세요'
        : finding.ruleId === 'JS_SEQUELIZE_SQL_INPUT_FLOW' ? '입력값이 SQL 문장에 직접 들어가는지 확인해 주세요'
        : finding.ruleId === 'JS_MONGO_WHERE_INPUT_FLOW' ? '입력값이 데이터베이스 실행 문자열에 들어가는지 확인해 주세요'
        : finding.ruleId === 'PY_FILE_PATH_INPUT_FLOW' ? '입력된 파일 경로의 제한을 확인해 주세요'
        : finding.ruleId === 'PY_UNSAFE_DESERIALIZATION_INPUT_FLOW' ? '외부 데이터의 복원 방식을 확인해 주세요'
        : finding.ruleId === 'PY_AUTHORIZATION_INVERTED_OWNER_GUARD' ? '사용자 비교와 차단 분기의 의도를 확인해 주세요'
        : finding.ruleId === 'PY_JWT_UNVERIFIED_ACCESS_DECISION' ? '토큰을 신뢰하기 전 서명 검증을 확인해 주세요'
        : finding.ruleId === 'PY_JWT_FIXED_SIGNING_KEY' ? '토큰 서명 키의 관리 방식을 확인해 주세요'
        : finding.ruleId.endsWith('_SENSITIVE_DATA_EXPOSURE') ? '보호할 정보가 응답·로그에 전달되는지 확인해 주세요'
        : finding.ruleId.endsWith('_ERROR_DETAIL_EXPOSURE') ? '내부 오류 정보가 응답에 포함되는지 확인해 주세요'
        : finding.ruleId==='PY_HTTP_TIMEOUT_REVIEW' ? '외부 요청의 대기 제한을 확인해 주세요' : '요청 값이 데이터베이스 쿼리에 들어갑니다'}</h4><p>{finding.message}</p>
      <p>{snapshot.validatedFindings == null ? '이 이력은 실행 경로 Finding 연결 이전의 기록입니다. 과거 결과를 새 기준으로 추측하여 승격하지 않습니다.'
        : '중간 처리 또는 실행 호출을 충분히 확인하지 못해 검증된 흐름 Finding으로 연결하지 않았습니다.'}</p>
      <p>{finding.recommendation}</p>
      <details className="technical-details"><summary>기술 근거와 한계</summary>
        <FlowEvidence finding={finding} />
      </details>
    </article>)}</div>
    {!python&&snapshot.nodeUses!=null&&<details className="coverage-details"><summary>Express 코드 실행·데이터 접근 근거 ({snapshot.nodeUses.length})</summary>
      <p>정적으로 연결된 요청·함수 호출만 확인합니다. 데이터 조회 근거는 소유권 검증의 증명이 아니며, 미확인 호출은 안전이나 취약점 확정으로 처리하지 않습니다.</p>
      <ul className="coverage-file-list">{snapshot.nodeUses.map((use,i)=><li key={i}>
        <code className="finding-location">{location(use.location)}</code>
        <span>{entryStageLabels[use.kind]??(use.kind==='INPUT_TO_EXECUTION'?'요청 입력이 실행 문자열로 전달됨':use.kind==='STATIC_OR_DATA_ONLY'?'고정 문자열 또는 일반 데이터 처리':use.kind==='DATA_QUERY_NOT_AUTHORIZATION_PROOF'?'데이터 조회 확인 · 접근권한은 미확인':use.kind==='INITIALIZATION_SUMMARY_MUST'?'제한된 모델 초기화·인스턴스 출처 확인':use.kind==='CONSTRUCTOR_SUMMARY_MUST'?'제한된 생성자의 필드 전달·읽기 효과 확인':use.kind==='CONSTRUCTOR_SUMMARY_UNKNOWN'?'생성자 효과를 확인하지 못함':use.kind==='CURSOR_CREATED_EXECUTION_NOT_OBSERVED'?'커서 구성 단계 · 이 근거만으로 실행은 미확인':'객체 출처 또는 값 전달을 확인하지 못함')}</span>
        <p>{use.operation} · {use.ruleId}</p>
        <ul>{use.trace.map((entry,j)=><li key={j}>{text(entry.kind)} · <code>{location(entry)}</code></li>)}</ul>
        {use.limitations.map((limit,j)=><p key={j}>{text(limit)}</p>)}
      </li>)}</ul>
    </details>}
    <details className="coverage-details"><summary>응답·로그 정보 전달 근거 ({snapshot.exposureUses?.length ?? '미기록'})</summary><ExposureDetails uses={snapshot.exposureUses}/></details>
    {python&&<details className="coverage-details"><summary>외부 요청 대기 제한 근거 ({snapshot.serviceUses?.length??'미기록'})</summary><ServiceStabilityDetails uses={snapshot.serviceUses}/></details>}
    {python && <details className="coverage-details"><summary>토큰 서명·사용 근거 ({snapshot.tokenUses?.length ?? '미기록'})</summary>
      <TokenSecurityDetails uses={snapshot.tokenUses} />
    </details>}
    {python && <details className="coverage-details"><summary>파일 접근·데이터 복원 근거 ({snapshot.resourceUses?.length ?? '미기록'})</summary>
      {snapshot.resourceUses == null ? <p>이 이력에는 파일 접근·데이터 복원 추적 기록이 없습니다. 과거 결과를 새 기준으로 판단하지 않습니다.</p>
        : <ul className="coverage-file-list">{snapshot.resourceUses.map((use, i) => <li key={i}>
          <code className="finding-location">{location(use.location)}</code><span>{text(use.kind)}</span>
          {use.defenses.map((d, j) => <span key={`d${j}`}>{text(d.kind)}</span>)}
          {use.limitations.map(l => <span key={l}>{text(l)}</span>)}
        </li>)}</ul>}
      <p>문자열 경계 검사를 확인했더라도 심볼릭 링크·운영 파일 권한을 보증하지 않습니다. 고정 데이터도 신뢰된 운영 데이터라고 확정하지 않습니다. Java·일반 Node.js 파일 흐름은 이번 범위에 포함되지 않습니다.</p>
    </details>}
    <details className="coverage-details"><summary>쿼리 값 처리와 방어 근거 ({snapshot.sqlUses.length})</summary>
      <ul className="coverage-file-list">{snapshot.sqlUses.map((sql, i) => <li key={i}>
        <code className="finding-location">{location(sql.location)}</code><span>{text(sql.kind)}</span>
        <span>{sql.defenses.map(d => text(d.kind)).join(' · ') || '확인한 바인딩 없음'}</span>
      </li>)}</ul><p>바인딩 확인은 인증·소유권 검증이나 모든 쿼리의 안전성을 보장하지 않습니다.</p>
    </details>
    {!python && <details className="coverage-details"><summary>서버 HTTP 요청 목적지 ({snapshot.httpUses?.length ?? '미기록'})</summary>
      {snapshot.httpUses == null ? <p>이 이력에는 HTTP 목적지 추적 기록이 없습니다. 과거 결과를 새 기준으로 판단하지 않습니다.</p>
        : <ul className="coverage-file-list">{snapshot.httpUses.map((http, i) => <li key={i}>
          <code className="finding-location">{location(http.location)}</code><span>{text(http.kind)}</span>
          <span>입력이 영향을 주는 영역: {text(http.controlledPart)}</span>
          {http.defenses.map((d, j) => <span key={`d${j}`}>{text(d.kind)}</span>)}
          {http.limitations.map(l => <span key={l}>{text(l)}</span>)}
        </li>)}</ul>}
      <p>고정된 주소나 허용 목록을 확인했더라도 리다이렉트·DNS 재해석·내부망 접근까지 안전하다고 보증하지 않습니다. SSRF는 서버가 의도하지 않은 주소로 요청하게 되는 위험입니다.</p>
    </details>}
    <details className="coverage-details"><summary>인증·권한 관련 문맥 ({snapshot.authorizationContexts.length})</summary>
      {snapshot.authorizationContexts.map((context, i) => <div key={i}>
        <h4 className="finding-location">{location(context.entry)}</h4>
        {context.details && <AuthorizationContextDetails details={context.details} />}
        <p>{context.checks.length ? `조건·로그인 문맥 ${context.checks.length}곳 확인` : '지원 범위에서 조건·로그인 문맥을 확인하지 못함'}</p>
        <ul>{[...context.checks, ...context.defenses].map((c, j) => <li key={j}>{text(c.kind)} · <code className="finding-location">{location(c)}</code></li>)}</ul>
        <p>권한 검증의 적절성은 확인되지 않았습니다. 검사가 보이지 않는다는 이유만으로 접근 권한 취약점으로 판단하지 않습니다.</p>
      </div>)}
    </details>
    <details className="coverage-details"><summary>파일별 구문 검사·추적 범위 ({snapshot.files.length})</summary>
      <ul className="coverage-file-list">{snapshot.files.slice(current * 10, current * 10 + 10).map((f, i) => <li key={i}>
        <code className="finding-location">{f.filePath}</code><span>{text(f.parseStatus)} · {text(f.flowStatus)} · 확인한 함수 {f.functionsAnalyzed}개</span>
        {python && <span>확인한 요청 진입점 {f.entrypoints}개{f.selectionReason ? ` · ${text(f.selectionReason)}` : ''}</span>}
        {!python&&f.selectionReason&&<span>입력 선택 근거 · {text(f.selectionReason)}</span>}
        {f.prepareCallSites != null && <span>{python ? 'SQL 실행 후보' : 'prepare'} 호출 구문 {f.prepareCallSites}곳 · 경로 확인 {f.tracedPrepareCallSites ?? '미기록'}곳 (모든 구문이 실제 SQL 호출이라는 뜻은 아님)</span>}
        {f.httpCallSites != null && <span>fetch 호출 구문 {f.httpCallSites}곳 · 목적지 추적 {f.tracedHttpCallSites ?? '미기록'}곳 (모든 HTTP client를 지원하는 것은 아님)</span>}
        {python && f.resourceCallSites != null && <span>파일·복원 API 후보 구문 {f.resourceCallSites}곳 · 호출 근거 추적 {f.tracedResourceCallSites ?? '미기록'}곳 (이름 후보이며 실제 API 사용을 모두 증명한 것은 아님)</span>}
        {f.limitations.map(l => <span key={l}>{text(l)}</span>)}
      </li>)}</ul>
      {snapshot.files.length > 10 && <nav className="finding-pagination" aria-label="서버 분석 파일 페이지">
        <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)}>이전</button><span>{current + 1} / {Math.ceil(snapshot.files.length / 10)}</span>
        <button type="button" disabled={(current + 1) * 10 >= snapshot.files.length} onClick={() => setPage(current + 1)}>다음</button>
      </nav>}
      <p>분석기 {snapshot.analyzerVersion} · 파서 {snapshot.parserVersion ?? '미실행'}</p>
      <ul>{snapshot.limitations.map(l => <li key={l}>{text(l)}</li>)}</ul>
    </details>
  </section>;
}

function PythonCoverageSummary({ snapshot }: { snapshot: ServerAnalysisSnapshot }) {
  const parsed = snapshot.files.filter(f => f.parseStatus === 'PARSED').length;
  const traced = snapshot.files.filter(f => f.functionsAnalyzed > 0).length;
  const limited = snapshot.files.filter(f => f.parseStatus === 'LIMIT_EXCEEDED').length;
  const failed = snapshot.files.filter(f => f.parseStatus === 'PARSE_FAILED').length;
  const entries = snapshot.files.reduce((sum, f) => sum + f.entrypoints, 0);
  return <div aria-label="Python 검사 범위 단계">
    {snapshot.authorizationContexts.some(c => c.details != null) && <p>권한 상세 문맥 {snapshot.authorizationContexts.filter(c => c.details != null).length}개 · 로그인 선언과 객체 접근 권한은 별도로 확인했습니다. 실제 활성 정책과 외부 보호는 미확인입니다.</p>}
    {snapshot.selectionCoverage && <p>공통 파일 수집기를 통과한 Python 파일 {snapshot.selectionCoverage.discoveredFiles}개 · 분석기에 전달 {snapshot.selectionCoverage.submittedFiles}개 · 미선택 {snapshot.selectionCoverage.omittedFiles}개</p>}
    <p>파일 기록 {snapshot.files.length}개 · 구문 파싱 {parsed}개 · 요청 진입점 {entries}개 · 값 전달을 추적한 파일 {traced}개</p>
    <p>자원 제한 {limited}개 · 파싱 실패 {failed}개 · 파싱 후 흐름 미추적 {snapshot.files.filter(f => f.parseStatus === 'PARSED' && f.functionsAnalyzed === 0).length}개</p>
    <p>파싱은 코드 구조를 읽었다는 뜻이며 보안 검사를 모두 마쳤다는 뜻이 아닙니다. 값 전달을 추적한 파일도 일부 함수·경로만 확인했습니다.</p>
    {(snapshot.limitations.includes('OMITTED_FILE_DETAILS_TRUNCATED') || (snapshot.selectionCoverage?.omittedDetails ?? 0) > 0) && <p>{text('OMITTED_FILE_DETAILS_TRUNCATED')}</p>}
  </div>;
}

function FlowEvidence({ finding }: { finding: ServerAnalysisSnapshot['findings'][number] }) {
  return <>
    <p className="finding-location">입력 위치: {location(finding.source)}</p><p className="finding-location">확인할 파일: {location(finding.sink)}</p>
    <ol>{finding.flow.map((step, index) => <li key={index}>{text(step.kind)} · <code className="finding-location">{location(step)}</code></li>)}</ol>
    <p>{finding.ruleId} · 흐름 근거 신뢰도 {finding.confidence} · {finding.disposition}</p>
    <p>확인한 처리: {finding.defenses.map(d => text(d.kind)).join(' · ') || '별도로 입증한 방어 처리 없음'}</p>
    <ul>{finding.limitations.map(item => <li key={item}>{text(item)}</li>)}</ul>
  </>;
}
