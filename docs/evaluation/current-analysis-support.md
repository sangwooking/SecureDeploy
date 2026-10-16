# SecureDeploy 현재 분석 지원 범위

- 기준일: 2026-10-16 (Asia/Seoul)
- 소스 기준: `a94170a57e4a075189d6ce8686f7b08d5b3be3da`
- 목적: 실제 프로젝트 5개를 같은 기준으로 평가하기 위한 지원 범위와 분석 공백의 기준선.

**현재 STANDARD는 선택된 파일의 정적 패턴 검사와 Maven/Gradle/npm 의존성 조회다. Java AST 기반 제한적 문맥 추출은 AI_ENHANCED의 Semantic Review에만 적용된다. 파일 수, COMPLETE, HIGH confidence는 전체 프로젝트의 안전을 증명하지 않는다.**

이 문서의 근거는 해당 커밋의 구현이다. 이번에는 분석 실행, 서버 환경/DB 조회, 브라우저 실행, 외부 GitHub/OSV/EPSS/KEV/OpenAI 호출을 하지 않았다. 아래 제한값은 저장소 설정/코드 기준이며 실제 실행 환경의 override는 미확인이다. 과거 Phase 문서의 계획이나 테스트 결과를 현재 검증 결과로 대체하지 않는다. 실제 평가에는 [공통 템플릿](project-evaluation-template.md)을 사용한다.

## 1. 분석 수준과 파일 선택

| 수준 | 의미 | 해석 주의 |
| --- | --- | --- |
| A | 코드 구조와 제한된 문맥을 분석할 수 있음 | 전체 call graph, 실행 도달 가능성, 공격 성공까지 증명한다는 뜻은 아님 |
| B | 정규식 또는 문자열 패턴만 검사함 | 해당 언어의 타입·입력 흐름·권한 의미를 이해하는 검사가 아님 |
| C | 의존성 또는 설정 일부만 검사함 | 패키지 조회가 애플리케이션 로직 검사로 확대 해석되면 안 됨 |
| D | 현재 지원하지 않음 | 미지원과 분석 완료 후 미발견을 구분 |

한 기술에도 기능별로 다른 수준이 적용된다. 설정 분석은 C로, 구현 방식이 행 단위 패턴이면 C(B)로 표기한다. 이는 취약점 판정 A/B/C/D와 다른 **지원 수준**이다.

| 기술/파일 | STANDARD | AI_ENHANCED에서 추가되는 범위 | 주요 공백 |
| --- | --- | --- | --- |
| Java `.java` / Spring MVC | B: SQL/CORS/permitAll 패턴 | A(제한적): Java 17 구문 AST, 특정 Spring mapping endpoint와 직접 호출 문맥 | 일반 Rule Engine은 AST를 사용하지 않음. 모든 Java 프레임워크·인가 흐름 지원 아님 |
| JavaScript `.js`, `.jsx` / TypeScript `.ts`, `.tsx` | B: 프론트 위험 사용 패턴 | Semantic AST 지원 없음 | Node/Express 인증·인가, JS taint/dataflow 미지원. React 전용 패턴을 다른 JS 파일에서도 검사 |
| `.min.js` | B: `.js`로 수집 | 없음 | 압축 코드 의미 복원 없음. 일부 룰의 신뢰도 후처리만 수행 |
| `application.yml`, `application.yaml`, `application.properties` | C(B): 지정 설정키 | Semantic의 Spring endpoint 자체는 아님 | `application-prod.yml` 등 임의 profile 파일은 이 이름 조건에 해당하지 않음 |
| `.env`, `.env.local`, `.env.development`, `.env.production` | C(B): 설정/secret 패턴 | Semantic AST 없음 | 모든 `.env*`가 아님. `.env.example`, `.env.test` 등은 제외됨 |
| `vite.config.js/ts`, `next.config.js/ts` | C(B): `FRONTEND_CONFIG`, 주로 secret 룰 | Semantic AST 없음 | 별도 타입이므로 일반 JS/TS 룰 전체가 적용되는 것은 아님. `.mjs`, `.cjs` 미수집 |
| `pom.xml`, `build.gradle`, `build.gradle.kts` | C: 내장 후보 룰 + 정적 OSV SCA | 의존성 로직 자체는 동일 | `.kts` 수집은 Kotlin 애플리케이션 분석 지원이 아님 |
| `package.json`, `package-lock.json`, `gradle.lockfile` | C: SCA; package scripts/name 후보 검사 등 | 동일 | 설치/빌드/실제 runtime graph 확인 없음 |
| `yarn.lock`, `pnpm-lock.yaml` | C: 기존 내장 후보 파서만 | 동일 | OSV용 manifest collector에는 미포함 |
| `Dockerfile`, `docker-compose.yml/yaml` | C(B): 컨테이너 설정 + 이미지 후보 | Semantic AST 없음 | 이미지 내용/OS package 스캔 없음. `Dockerfile.prod`, `compose.yml` 등은 이름 조건 밖 |
| `.github/workflows/` 아래 `.yml/.yaml` | C(B): 지정 Actions 패턴 | Semantic AST 없음 | CI 실제 실행·권한 그래프·GitLab/Jenkins 설정 전반 미지원 |
| `k8s/` 아래 `.yml/.yaml`, 이름이 `deployment`, `service`, `ingress`인 `.yml/.yaml` | C(B): 지정 K8s 패턴 | Semantic AST 없음 | 전체 YAML/Helm 렌더링/클러스터 실제 상태 미지원 |
| `nginx.conf`, `default.conf`, `*.nginx.conf` | C(B): 지정 Nginx 설정 | Semantic AST 없음 | include 해석, 외부 TLS termination, 실제 network exposure 미확인 |
| Python `.py` | D | D: Semantic Java 전용 | 문자열 secret 일반 검사도 `.py`에는 실행되지 않음 |
| `requirements.txt`, `requirements.in`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock` | D | D | Python 의존성의 OSV 조회 없음 |
| Kotlin `.kt`, Go, Rust, PHP, Ruby, C/C++, C#, Dart, Vue SFC, HTML/CSS, Terraform `.tf` | D: 해당 소스 자체 | D: Semantic 범위 밖 | 같은 저장소의 지원 manifest/설정만 검사될 수 있음 |
| README/Markdown/임의 JSON/YAML | D: 해당 파일 자체 | D | `docs/` 안의 `.js` 등 지원 확장자는 별도. 문서 경로 FP 조건이 있다고 `.md` 수집을 뜻하지 않음 |

파일명은 collector에서 소문자로 비교한다. Kubernetes/Actions는 경로 조건도 사용한다. 이후 개별 룰의 추가 조건이 있으므로 collector 수집 여부와 룰 실행 여부를 별도로 대조한다.

근거: [ProjectFileCollector](../../src/main/java/com/securedeploy/project/service/ProjectFileCollector.java), [RuleFileTypes](../../src/main/java/com/securedeploy/rule/rules/RuleFileTypes.java), [SecuritySliceCollector](../../src/main/java/com/securedeploy/ai/semantic/SecuritySliceCollector.java).

## 2. 호출 흐름과 결과의 의미

```text
ZIP 저장/안전 해제 또는 익명 GitHub default-branch 수집
  -> ProjectScanner: 지원 파일 선택, UTF-8 읽기, 자원 제한
  -> VulnerabilityRuleEngine: 각 파일에 각 룰 evaluate 호출
  -> FalsePositiveAnalyzer: 유지/제외/severity/confidence 조정/중복 제거
  -> SnippetCollector: 제한된 기존 AI Audit용 snippet 수집
  -> Rule 기반 참고 점수와 vulnerabilityCount
  -> ScaService: 정적 inventory, EXACT 버전 OSV 조회
  -> AI_ENHANCED일 때만 Java Security Slice 수집
  -> Threat Intelligence: SCA finding의 CVE에 EPSS/KEV 보조 정보
  -> ComparisonContext 수집
  -> Project 연결, Review/SCA/Risk/source/context 저장
  -> Remediation snapshot -> Semantic snapshot -> 비교 snapshot
```

- Spring 등록 룰은 **27개 클래스 / 35개 ruleId**다. `List<VulnerabilityRule>`를 주입하며 실제 대상 판정은 각 `evaluate()`가 한다.
- `vulnerabilityCount`와 참고 점수는 **FP 후처리 후 Rule 결과**다. 원시 룰 매치 수가 아니며 SCA advisory/분석 공백/AI 후보 수와 합산할 수 없다.
- 배포 판단의 우선 필드는 `riskAssessment.prioritizedDeploymentAssessment`다. `securityScore`와 `deploymentStatus`는 기존 룰 중심 참고값이다.
- 우선순위는 `BLOCKING`, `REVIEW_REQUIRED`, `SHOULD_FIX`, `INFORMATIONAL`. SCA 미완료는 분석 공백 항목이며 확정 취약점이 아니다.
- 내장 dependency 후보와 OSV는 출처가 다르다. 정확한 package/version과 조회 완성도 등을 조건으로 correlation을 남겨 Priority 중복 합산을 줄인다. 원본 Rule 결과는 보존된다. Docker 후보 중복까지 이 상관 처리의 대상인 것은 아니다.
- 코드/수집 단계 예외에는 룰별 격리·실패 ledger가 없다. 예외가 전파되면 요청이 실패한다. SCA·AI 일부 실패는 별도 상태로 처리한다.

근거: [SecurityReviewFacade](../../src/main/java/com/securedeploy/review/service/SecurityReviewFacade.java), [Rule Engine](../../src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java), [Review DTO](../../src/main/java/com/securedeploy/review/dto/SecurityReviewResponse.java), [Risk Engine](../../src/main/java/com/securedeploy/risk/service/RiskPrioritizationEngine.java), [DependencyFindingCorrelator](../../src/main/java/com/securedeploy/risk/service/DependencyFindingCorrelator.java).

## 3. Rule Engine 전체 목록

Severity는 최초 룰 출력 기준이다. FP 후처리와 Risk Priority는 별도다. 아래 조건은 구현이 검사하는 범위이지 공격 성공의 증명이 아니다. 많은 룰이 한 줄만 검사하므로 주석·문자열·여러 줄 표현·다른 파일의 방어 처리에 대한 한계가 있다.

### Java 및 Spring 설정 10종

설정 파일은 1절의 지정 application/env 파일만을 뜻한다. `ConfigFileParser`는 평면 key-value와 YAML 들여쓰기 stack을 사용하는 간이 파서이며 완전한 YAML/profile 해석기가 아니다.

| ruleId / 구현 | 대상·수준 | 초기 severity | 검사 조건 및 경계 |
| --- | --- | --- | --- |
| [HARDCODED_PASSWORD](../../src/main/java/com/securedeploy/rule/rules/HardcodedPasswordRule.java) | 설정 C(B) | HIGH | password 키와 `.password` suffix, 환경변수 표현/일부 마스킹 값 제외. Java의 임의 password 변수 검사는 아님 |
| [HARDCODED_SECRET](../../src/main/java/com/securedeploy/rule/rules/HardcodedSecretRule.java) | 설정 C(B) | HIGH | secret/api.key 계열 지정 키와 suffix, 환경변수 표현 제외 |
| [WEAK_JWT_SECRET](../../src/main/java/com/securedeploy/rule/rules/WeakJwtSecretRule.java) | 설정 C(B) | HIGH | jwt.secret 32자 미만 또는 단순 값/문자 패턴. 알고리즘별 암호학적 강도 검증 아님 |
| [CORS_WILDCARD](../../src/main/java/com/securedeploy/rule/rules/CorsWildcardRule.java) | Java B | MEDIUM | 한 줄의 `@CrossOrigin` wildcard 패턴. 다른 CORS 구성 전반은 미지원 |
| [DANGEROUS_SQL](../../src/main/java/com/securedeploy/rule/rules/DangerousSqlRule.java) | Java B | HIGH | 문자열 결합된 createNativeQuery/prepareStatement, Statement/createStatement, SQL 키워드+결합. 사용자 입력 source-sink 추적 없음 |
| [PERMIT_ALL_USAGE](../../src/main/java/com/securedeploy/rule/rules/PermitAllUsageRule.java) | Java B | MEDIUM | `.permitAll()` 사용. 공개 로그인 API인지 실제 matcher 영향 범위인지 판단하지 않음 |
| [DEBUG_ENABLED](../../src/main/java/com/securedeploy/rule/rules/DebugEnabledRule.java) | 설정 C(B) | MEDIUM | 정규화된 debug=true |
| [EXPOSED_ACTUATOR](../../src/main/java/com/securedeploy/rule/rules/ExposedActuatorRule.java) | 설정 C(B) | HIGH | exposure.include 값이 정확히 `*`. 네트워크 접근/추가 인증은 미확인 |
| [INSECURE_COOKIE](../../src/main/java/com/securedeploy/rule/rules/InsecureCookieRule.java) | 설정 C(B) | MEDIUM | secure/http-only 계열 키 false. 일부 suffix가 넓고 Java Cookie setter는 검사하지 않음 |
| [STACKTRACE_EXPOSURE](../../src/main/java/com/securedeploy/rule/rules/StacktraceExposureRule.java) | 설정 C(B) | MEDIUM | server.error.include-stacktrace=always |

근거: [ConfigFileParser](../../src/main/java/com/securedeploy/rule/rules/ConfigFileParser.java), [AbstractPatternRule](../../src/main/java/com/securedeploy/rule/rules/AbstractPatternRule.java).

### 프론트엔드 6종

| ruleId / 구현 | 대상·수준 | 초기 severity | 검사 조건 및 경계 |
| --- | --- | --- | --- |
| [REACT_DANGEROUS_HTML](../../src/main/java/com/securedeploy/rule/rules/ReactDangerousHtmlRule.java) | JS/JSX/TS/TSX B | HIGH | dangerouslySetInnerHTML 포함. sanitizer 적용이나 실제 사용자 입력 연결을 해석하지 않음 |
| [LOCAL_STORAGE_TOKEN](../../src/main/java/com/securedeploy/rule/rules/LocalStorageTokenRule.java) | JS/JSX/TS/TSX B | HIGH | 같은 줄 localStorage + setItem/getItem + token/jwt 키워드. literal key AST 검사 아님; sessionStorage 룰 아님 |
| [HARDCODED_FRONTEND_SECRET](../../src/main/java/com/securedeploy/rule/rules/HardcodedFrontendSecretRule.java) | JS/TS/React, 지정 env, frontend config B/C | HIGH | API_KEY/SECRET/TOKEN 대입 및 secret 계열 문자열 대입; JS 문자열은 8자 이상 조건. 일부 dummy는 룰에서 먼저 제외 |
| [INSECURE_API_URL](../../src/main/java/com/securedeploy/rule/rules/InsecureApiUrlRule.java) | JS/TS/React + 지정 설정 B/C | MEDIUM | http:// 문자열, localhost/127.0.0.1 prefix 제외. 실제 API 통신인지 의미 분석 없음 |
| [UNVALIDATED_REDIRECT](../../src/main/java/com/securedeploy/rule/rules/UnvalidatedRedirectRule.java) | JS/JSX/TS/TSX B | MEDIUM | href/window.location.assign + 같은 줄 redirectUrl/returnUrl/next. 앞선 검증 여부는 미확인 |
| [PACKAGE_JSON_RISK](../../src/main/java/com/securedeploy/rule/rules/PackageJsonRiskRule.java) | package.json C(B) | MEDIUM/LOW | curl/wget/rm -rf/sudo/chmod 777 또는 6개 주의 패키지명. JSON scripts 영역을 구조적으로 한정하지 않는 행 검사 |

### Docker와 배포 설정 15종

| ruleId / 구현 | 대상·수준 | 초기 severity | 검사 조건 및 경계 |
| --- | --- | --- | --- |
| [DOCKER_ROOT_USER](../../src/main/java/com/securedeploy/rule/rules/DockerRootUserRule.java) | Dockerfile C(B) | HIGH | USER root/0 또는 파일 전체에 USER 부재. final stage/base image 기본 사용자 미해석 |
| [DOCKER_LATEST_TAG](../../src/main/java/com/securedeploy/rule/rules/DockerLatestTagRule.java) | Dockerfile/compose C(B) | MEDIUM | FROM/image latest 패턴. 전체 image reference 문법 지원 아님 |
| [DOCKER_SECRET_ENV](../../src/main/java/com/securedeploy/rule/rules/DockerSecretEnvRule.java) | Dockerfile C(B) | HIGH | ENV의 민감 키와 `=` 패턴. ARG/모든 ENV 문법을 포괄하지 않음 |
| [DOCKER_PRIVILEGED](../../src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java) | compose C(B) | HIGH | privileged: true 행 |
| [DOCKER_HOST_NETWORK](../../src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java) | compose C(B) | MEDIUM | network_mode: host 행 |
| [GITHUB_ACTIONS_UNPINNED](../../src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java) | Actions C(B) | MEDIUM | @main/@master/@develop 또는 @ 없음. 40자리 SHA는 제외; 모든 non-SHA ref를 잡는 것은 아니며 local action도 오탐 검토 필요 |
| [GITHUB_ACTIONS_SECRET_ECHO](../../src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java) | Actions C(B) | HIGH | 같은 줄 echo + secrets expression |
| [GITHUB_ACTIONS_CURL_PIPE](../../src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java) | Actions C(B) | HIGH | 같은 줄 curl/wget + pipe + sh/bash 문자열. shell AST 아님 |
| [K8S_PRIVILEGED_CONTAINER](../../src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java) | K8s C(B) | HIGH | privileged: true 행 |
| [K8S_LATEST_IMAGE](../../src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java) | K8s C(B) | MEDIUM | image latest 패턴 |
| [K8S_NODEPORT_EXPOSURE](../../src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java) | K8s C(B) | MEDIUM | type: NodePort. 실제 외부 노출 여부 미확인 |
| [K8S_SECRET_PLAIN_TEXT](../../src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java) | K8s C(B) | HIGH | kind: Secret 이후 지정 민감 키 행. data/stringData/문서 경계/base64 암호화 여부를 구조적으로 검증하지 않음 |
| [NGINX_DIRECTORY_LISTING](../../src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java) | Nginx C(B) | MEDIUM | autoindex on |
| [NGINX_SERVER_TOKENS](../../src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java) | Nginx C(B) | LOW | server_tokens on |
| [NGINX_HTTP_ONLY](../../src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java) | Nginx C(B) | MEDIUM | 파일 전체 listen 80 존재, 443/ssl 문자열/특정 HTTPS redirect 부재. server block·include·상위 프록시 미해석 |

### 내장 dependency 후보 4종

| ruleId / 구현 | 대상·수준 | 초기 severity | 검사 조건 및 경계 |
| --- | --- | --- | --- |
| [VULNERABLE_NPM_DEPENDENCY](../../src/main/java/com/securedeploy/rule/rules/VulnerableNpmDependencyRule.java) | package.json/npm·yarn·pnpm lock C | HIGH/MEDIUM | 구형 행 파서 + 내장 catalog. OSV의 구조적 npm 파서와 별개 |
| [VULNERABLE_MAVEN_DEPENDENCY](../../src/main/java/com/securedeploy/rule/rules/VulnerableMavenDependencyRule.java) | pom.xml C | HIGH | 구형 행 파서 + 내장 artifact/version 후보 |
| [VULNERABLE_GRADLE_DEPENDENCY](../../src/main/java/com/securedeploy/rule/rules/VulnerableGradleDependencyRule.java) | build.gradle(.kts) C | HIGH | 지정 literal/map notation + 내장 후보 |
| [OUTDATED_DOCKER_BASE_IMAGE](../../src/main/java/com/securedeploy/rule/rules/OutdatedDockerBaseImageRule.java) | Dockerfile/compose C | MEDIUM | FROM/image의 지정 image/tag 후보. 이미지 CVE 스캔 아님 |

내장 catalog는 event-stream, lodash, minimist, axios, serialize-javascript와 log4j-core, spring-webmvc, jackson-databind, commons-collections 및 일부 Docker image/tag를 다룬다. `cveId`는 null로 생성된다. 문구와 업데이트 경계값은 저장된 휴리스틱이며 **현재 모든 CVE를 해결하는 안전 버전 목록이 아니다**. Java 후보는 artifact 이름 중심 매칭이고 구형 npm 파서는 `^`/`~`를 제거한다. OSV의 EXACT 판정과 동일한 신뢰도로 취급하지 않는다.

근거: [VulnerableDependencyCatalog](../../src/main/java/com/securedeploy/dependency/advisory/VulnerableDependencyCatalog.java), [구형 npm 파서](../../src/main/java/com/securedeploy/dependency/parser/PackageJsonDependencyParser.java), [내장 후보 evidence](../../src/main/java/com/securedeploy/rule/rules/DependencyRuleMatchFactory.java).

## 4. False Positive와 긴 문자열 처리

- 대상 8개: HARDCODED_PASSWORD, HARDCODED_SECRET, HARDCODED_FRONTEND_SECRET, DOCKER_SECRET_ENV, K8S_SECRET_PLAIN_TEXT, GITHUB_ACTIONS_SECRET_ECHO, LOCAL_STORAGE_TOKEN, REACT_DANGEROUS_HTML.
- 그 외 룰은 현재 `falsePositiveRisk=LOW`, `confidence=HIGH`, 명확한 룰 패턴이라는 메모를 기본 부여한다. **실제 credential 유효성/악용 가능성 확률로 보정된 confidence가 아니다.**
- source의 해당 한 줄과 evidence, 경로를 함께 사용한다. 테스트/샘플/fixture/dataset, minified, placeholder, 알려진 JWT/API-key 모양 등을 판정한다. 함수 간 값 사용 흐름을 추적하지 않는다.
- secret 매치의 lock integrity/resolved, 생성 산출물, 실행 문맥 없는 data URL 등은 제외할 수 있다. 제외된 매치와 사유의 집계/목록은 최종 API에 보존되지 않는다.
- 긴 문자열 처리는 **독립적인 새 탐지 룰이 아니라 기존 매치 후처리**다. 대입 값 64자 이상 + Shannon entropy 3.5 이상은 credential 후보 유지 조건이다. HTTP URL은 이 entropy 조건에서 제외한다. 500자 이상 base64성/static-data 조건과 eval/HTML/atob/redirect 같은 같은 줄 문맥도 사용한다.
- 강한 패턴/고엔트로피 판정은 정적 데이터 downgrade보다 먼저 실행된다. UUID/hash 전용 전역 제외기나 실제 키 인증 검증은 없다. UUID/hash/URL이 민감한 변수명 아래 올 때와 정상 변수 아래 올 때를 구분해 평가해야 한다.
- 중복 제거 key는 `ruleId + filePath + line + evidence`. 동일 값의 모든 파일·행을 하나로 합치는 정책은 아니다.
- 최종 metadata는 DTO/DB 및 카드의 판단 근거로 이어진다. evidence는 마스킹된 결과만 사용하고 실제 프로젝트 평가 문서에도 비밀값을 복사하지 않는다. 모든 표현의 완전한 masking을 보장한다고 주장하지 않는다.

근거: [FalsePositiveAnalyzer](../../src/main/java/com/securedeploy/rule/filter/FalsePositiveAnalyzer.java), [Vulnerability DTO](../../src/main/java/com/securedeploy/review/dto/VulnerabilityResultResponse.java), [CodeFindingCard](../../frontend/src/components/CodeFindingCard.tsx).

## 5. Java AST와 AI Semantic Review

### 실제 구조 분석 범위

`SecuritySliceCollector`는 JDK `JavaCompiler` / `JavacTask.parse()`를 `-proc:none --release 17`로 사용한다. `analyze()`, `generate()`, annotation processor, 대상 클래스 로드, 대상 빌드는 실행하지 않는다. JDK compiler 부재 시 available=false다.

- 최상위 class의 method, field/parameter 타입 표기, 명시 import를 읽는다. 생성자·중첩 class 내부 등의 전체 모델링은 하지 않는다.
- RequestMapping/GetMapping/PostMapping/PutMapping/DeleteMapping/PatchMapping의 literal 경로를 endpoint로 선택한다. 배열/상수 기반 경로, functional route, custom composed annotation은 전체 지원하지 않는다.
- 필드/파라미터/this의 수신자, method name, 인자 수가 유일하게 맞는 직접 구문 호출을 최대 2단계 연결한다. entry 포함 최대 4개 method 후, 이름상 SecurityConfig/Filter/Interceptor/AuthenticationProvider의 method를 최대 2개 더 붙인다.
- PreAuthorize/PostAuthorize/Secured/RolesAllowed는 **선언 존재** 신호다. 인증이 실제 적용되는지 증명하지 않는다. Spring proxy/DI 구현체·overload 타입·dynamic dispatch·공통 filter 전체가 해석되는 것은 아니다.
- 기본 slice 선택 4개. 같은 우선순위에서는 파일/행 순서를 사용한다. 큰 프로젝트의 모든 endpoint를 검사하지 않는다.
- 문자열/문자 literal을 먼저 마스킹하고 method excerpt와 위치를 만든다. 검토 범위 밖의 코드, 잘린 method, 제거된 literal 때문에 판단 근거가 부족할 수 있다.

### 모델 결과의 검증과 경계

Semantic은 AI_ENHANCED + 사용 가능한 OpenAI provider + request budget + Java endpoint slice 조건을 만족해야 호출된다. STANDARD 또는 template에서는 자동 Semantic 외부 호출이 없다. AI_ENHANCED 선택만으로 실제 실행을 보장하지 않는다.

Strict Structured Output 후 slice/context ID, 파일명, 함수명, 행 범위, 검증 단계, 참조 finding, 일부 주장 문자열을 검사한다. 존재하지 않는 위치를 거부하지만 **실제 보안 해석이 옳다는 검증은 아니다**. 중복/거부 수와 검증 상태를 snapshot에 남긴다. 권한 선언이 있는 접근제어 후보는 confidence를 낮춘다.

후보 유형은 IDOR/인가 우회/인증 누락/접근통제/업무 흐름 우회/파일 접근/path traversal/SSRF/명령 주입/역직렬화/민감정보/암호화/세션/기타다. 이 enum의 존재는 각 유형의 완전한 탐지 지원을 의미하지 않는다.

결과는 `AI_SECURITY_CANDIDATE`, `REVIEW_REQUIRED`, `verificationRequired=true`로 독립 유지한다. Rule severity/confidence/count/score 및 deterministic 배포 판단을 변경하지 않는다. 기존 동일 계열 finding의 보조 근거는 별도 배열에 둔다. 실패 시 가짜 template 후보를 생성하지 않는다.

근거: [Slice collector](../../src/main/java/com/securedeploy/ai/semantic/SecuritySliceCollector.java), [SemanticReviewService](../../src/main/java/com/securedeploy/ai/semantic/SemanticReviewService.java), [Output validator](../../src/main/java/com/securedeploy/ai/semantic/SemanticOutputValidator.java), [Candidate](../../src/main/java/com/securedeploy/ai/semantic/SemanticCandidate.java), [Real provider](../../src/main/java/com/securedeploy/ai/service/RealOpenAiProvider.java).

### 기존 AI Audit와 혼동 금지

별도 수동 AI Audit는 Rule 결과/통계 + `SnippetCollector`의 Java/프론트/설정/DevOps 일부 snippet을 쓴다. 최대 10개 파일, 앞 80줄/약 1,500자이며 생략 안내가 추가될 수 있다. Audit prompt는 약 12,000자 제한이다. 이것은 Semantic의 AST 기반 slice와 다른 기능이다. 저장된 snippet 또는 template Audit 설명이 존재해도 실제 외부 AI의 전체 코드 검토를 했다고 평가하면 안 된다.

근거: [SnippetCollector](../../src/main/java/com/securedeploy/ai/context/SnippetCollector.java), [AiReviewService](../../src/main/java/com/securedeploy/ai/service/AiReviewService.java), [PromptBuilder](../../src/main/java/com/securedeploy/ai/prompt/PromptBuilder.java).

## 6. SCA와 Threat Intelligence 지원

| 입력 | 실제 OSV SCA 지원 | 남는 공백 |
| --- | --- | --- |
| pom.xml | 안전한 XML 파싱, root dependencies, scope, 같은 POM의 단순 properties 치환(최대 10회) | parent/BOM/dependencyManagement 해석, profile 활성화, transitive graph/원격 POM 없음. profile은 경고. XML 위치 line=0 |
| build.gradle(.kts) | implementation/api/compileOnly/runtimeOnly/testImplementation/testRuntimeOnly/annotationProcessor/compile/runtime의 literal 좌표, 단순 Groovy map, 주석 제거 | 임의 Groovy/Kotlin 실행 없음. version catalog/함수/계산/멀티라인 DSL은 제한적. 인식된 미해결 표현만 UNRESOLVED이므로 모든 누락 표현이 기록되는 것은 아님 |
| gradle.lockfile | group:artifact:version=configuration, 같은 디렉터리 선언과 결합 | lock-only direct 여부 미확인, 전체 의존성 graph 없음 |
| package.json | JSON 구조 파싱, dependencies/devDependencies/optionalDependencies/peerDependencies | range/tag/workspace/Git/URL은 OSV 조회 안 함. sibling package-lock 우선. line=0 |
| package-lock.json | v2/v3 packages, nested/workspace/direct 후보, 설치 경로별 정보 | v1 미지원. link/non-registry resolution은 UNRESOLVED. 실제 설치 검증 아님. line=0 |
| yarn/pnpm lock, Python manifest, Docker image | OSV collector 미지원 | 다른 내장 후보 룰이 실행되어도 OSV 검사가 완료된 것은 아님 |

- Maven과 Gradle은 OSV `Maven`, npm은 `npm` ecosystem. `EXACT`는 정적으로 읽은 버전이지 실제 설치/실행 버전을 확인했다는 뜻이 아니다.
- `EXACT`, `RANGE`, `UNRESOLVED`를 구분한다. querybatch는 EXACT에만 호출하며 URL/Git spec은 민감정보 보호를 위해 중립 marker로 처리한다.
- batch에서 ID를 받고 advisory 상세를 별도 조회한다. 상세 실패 시 알려진 ID를 보존하고 severity/fix 미확인 및 경고를 남긴다. 완료 package 조회 수와 상세 조회 성공 수는 같은 지표가 아니다.
- fixedVersions는 해당 package/advisory의 수정 event 목록이다. 하나를 임의 선택해 모든 문제의 안전 하한으로 제시하면 안 된다. CVSS vector만 있으면 숫자 점수를 새로 계산하지 않으며 미확인 값은 null/UNKNOWN이다.
- `NO_MANIFEST`는 지원 collector에 매칭된 파일이 없다는 뜻이다. 미지원 manifest 존재 여부를 별도 inventory로 남기지 않는다.
- manifest는 있지만 인식된 component가 없고 경고도 없으면 COMPLETE가 가능하다. 파서가 이해하지 못한 문법까지 분석 완료했다는 뜻은 아니다.
- SCA CVE에만 EPSS/KEV를 조회한다. CVE가 없으면 NOT_APPLICABLE이며 이를 악용 위험 없음으로 해석하지 않는다. 실패·stale·missing은 저장 시점과 함께 확인한다. 코드 finding 전체에 EPSS를 적용하는 구조가 아니다.
- 사용자가 직접 입력한 이름/버전의 supplemental lookup은 source에서 확인한 dependency와 별개이며 기존 snapshot/배포 판단을 수정하지 않는다.

근거: [ScaManifestCollector](../../src/main/java/com/securedeploy/sca/parser/ScaManifestCollector.java), [Maven parser](../../src/main/java/com/securedeploy/sca/parser/MavenManifestParser.java), [Gradle parser](../../src/main/java/com/securedeploy/sca/parser/GradleManifestParser.java), [npm parser](../../src/main/java/com/securedeploy/sca/parser/NpmManifestParser.java), [VersionClassifier](../../src/main/java/com/securedeploy/sca/parser/VersionClassifier.java), [ScaService](../../src/main/java/com/securedeploy/sca/service/ScaService.java), [OsvClient](../../src/main/java/com/securedeploy/sca/client/OsvClient.java), [Advisory mapper](../../src/main/java/com/securedeploy/sca/client/OsvAdvisoryMapper.java), [Severity mapper](../../src/main/java/com/securedeploy/sca/client/OsvSeverityMapper.java), [Threat service](../../src/main/java/com/securedeploy/threatintel/service/ThreatIntelligenceService.java), [Supplemental service](../../src/main/java/com/securedeploy/sca/service/SupplementalDependencyService.java).

## 7. 제외 정책과 자원 제한

### 제외 정책

`node_modules`, `.git`, `build`, `dist`, `target`, `out`, `.gradle`, `coverage`, `vendor`라는 경로 segment를 제외한다. 공통 정책은 대소문자를 구분하며 Git exporter에는 `.git` 대소문자 추가 차단이 있다. 일반 `.gitignore`/사용자 ignore 설정을 해석하지 않는다. test/mock/fixture/sample/dataset/generated는 이 공통 제외 목록이 아니며 지원 확장자는 수집 후 FP 평가될 수 있다.

GitHub는 익명 읽기 전용 default branch depth=1 수집이다. submodule 재귀 fetch, LFS 실파일 다운로드, symlink 따라가기를 하지 않고 성공한 source metadata에 수/제한 안내를 남긴다. ZIP도 LFS pointer를 source로 분석하지 않지만 동일한 제외 집계를 DTO에 남기지는 않는다.

ZIP의 제외 파일도 해제 바이트/entry 예산을 소비한다. Git exporter도 무시할 blob을 포함한 크기/entry 제한을 확인한다. 제외 목록이 큰 archive의 모든 자원 제한을 우회하게 해주지는 않는다.

### 기본 제한값

MB/GB는 Spring DataSize 설정 값이다. 실제 환경 override/Reverse proxy 제한/디스크 여유/프로세스 heap은 평가 실행마다 따로 기록한다.

| 단계 | 저장소 기본값/고정 제한 | 초과·제약 효과 |
| --- | --- | --- |
| Multipart ZIP | 파일 200MB, 요청 205MB, 메모리 threshold 0B | 413, 업로드 정책 안내 |
| ZIP 해제 | 총 1GB, archive entry 50,000, 생성 파일·부모 디렉터리도 별도 50,000 한도 | 413. Zip Slip/손상은 400. 비율만으로 ZIP bomb 판정하는 방식 아님 |
| 공통 source 읽기 | 개별 분석 파일 32MB, 분석 파일 합계 128MB, 총 500,000줄, 분석 파일 수 50,000 | 413으로 요청 실패; 부분 결과를 성공 저장하지 않음 |
| GitHub 수집 | 60초(설정 clamp 1~300초), 다운로드 200MB, HTTP 요청 12회, 동시 수집 2개 | timeout 504, 크기/요청 수 413, 동시 슬롯 초과 429 |
| SCA inventory | manifest 100개, 파일당 2,000,000자, dependency 위치 5,000개 | 경고와 부분 결과; 공통 scanner 제한과 별개 |
| OSV | unique package/version 500개, advisory 상세 100개, batch 100개 | 미조회/상세 미확인 경고 |
| OSV HTTP | connect/read 각 5초, 요청 예약 예산 30초, 최대 50회, 응답당 2,000,000 bytes, 결과 2,000개 | PARTIAL/UNAVAILABLE. 진행 중 요청까지 정확히 30초 안에 끝나는 hard deadline은 아님 |
| EPSS/KEV | timeout 5초, 예산 20초, CVE 300개, cache 6시간, 실패 backoff 60초, EPSS max age 2일 | 조회 상태/신선도/경고에 반영 |
| Semantic 인덱싱 | Java 200개/합계 2,000,000자, 개별 파일 100,000자, 3,000 methods, 루프 deadline 8초 | skip/unparsed 합산 notice; 단일 parser 실행을 중단하는 hard timeout 아님 |
| Semantic 요청 | slice 4개, excerpt 1,800자, policy+data 24,000자, 요청 1회, output 4,000 tokens, 후보 12개 | slice 생략/UNAVAILABLE/validation 실패 등. 전체 OpenAI 전송 토큰 상한과 문자 제한은 서로 다름 |

근거: [application.yml](../../src/main/resources/application.yml), [UploadPolicy](../../src/main/java/com/securedeploy/upload/service/UploadPolicy.java), [ZipExtractService](../../src/main/java/com/securedeploy/upload/service/ZipExtractService.java), [ProjectScanner](../../src/main/java/com/securedeploy/project/service/ProjectScanner.java), [ProjectIgnorePolicy](../../src/main/java/com/securedeploy/project/service/ProjectIgnorePolicy.java), [GitTreeExporter](../../src/main/java/com/securedeploy/github/service/GitTreeExporter.java), [CloneBudget](../../src/main/java/com/securedeploy/github/service/CloneBudget.java), [SemanticProperties](../../src/main/java/com/securedeploy/ai/semantic/SemanticProperties.java).

## 8. 누락 상태의 Backend API UI 연결

아래 UI 평가는 컴포넌트 코드 기준이다. 실제 브라우저 표시·시인성·모바일 상태는 이번 작업에서 미확인이다.

| 상황 | Backend/API | UI 표현 | 남는 구분 문제 |
| --- | --- | --- | --- |
| 미지원 언어/확장자 | collector Optional.empty, 스캔 목록에 안 들어감 | 별도 미지원 파일 목록 없음 | 실제 존재하나 미지원인지 알기 어려움 |
| 공통 제외 디렉터리 | skip; policy API는 정적 제외 목록 반환 | 업로드 안내에 제외 폴더 표시 | 실제 이번 실행에서 제외된 파일 수/경로/reason은 없음 |
| Git submodule/LFS/symlink | 성공 시 sourceMetadata limitations/count | GitHubSourceInfo에 안내 | ZIP LFS 및 일반 미지원과 같은 coverage schema는 아님 |
| 지원 파일 0개 | Facade 400, 분석 가능한 파일 없음 안내 | API message 오류 표시 | 저장되는 실패 Review는 없음; 0건 정상 분석이 아님 |
| 파일 읽기/UTF-8 실패 | Scanner 400, 요청 실패 | 오류 메시지 | 실패 파일의 구조화된 경로/단계 ledger 없음 |
| source 크기/줄/entry 초과 | 413, 요청 실패 | 업로드/분석 제한 메시지 | 일부 읽은 파일의 완료 결과로 취급하지 않음 |
| GitHub URL/접근/timeout | 400/502/504 등, 수집 전 실패면 Review 없음 | 오류 메시지 | 접근 401/403/404의 upstream 구분은 같은 사용자 안내로 합쳐짐 |
| 간이 설정/내장 후보 파서의 미인식 문법 | 행을 건너뛰거나 빈 매치 목록 가능; 별도 parser status 없음 | 결과가 없으면 일반 미발견 목록 | YAML 구조/여러 줄 선언을 이해하지 못한 것과 정상 미발견을 구분하기 어려움 |
| 지원 SCA manifest 파싱 실패/자원 제한 | warnings + PARTIAL 또는 UNAVAILABLE; collector 자체 예외는 UNAVAILABLE | “일부만 확인됨”/“조회하지 못함”, 경고 상세 | parser failure와 resource limit 일부는 같은 경고, 인식되지 않은 DSL은 누락 가능 |
| SCA manifest 없음 | NO_MANIFEST | “지원하는 의존성 파일 없음” + 안전 미확인 주의 | manifest 부재와 다른 생태계 manifest 존재를 세분화하지 않음 |
| SCA 비활성/과거 snapshot 없음 | DISABLED 또는 sca=null | 비활성/결과 없음·재분석 안내 | 취약점 0건과 다름 |
| 라이브러리 이름/버전 미확인 | RANGE/UNRESOLVED, 조회 제외; risk reviewRequirements | “버전 확인 필요”, 불완전 dependency 카드/다음 행동 | parser가 아예 인식 못한 선언은 목록에도 없을 수 있음 |
| OSV 실패/시간/상한 | PARTIAL/UNAVAILABLE + warnings, known ID 보존 | 조회 불가/일부 확인, 미조회는 안전 아님 | component별 최종 HTTP/조회 완료 상태는 별도 필드로 남지 않아 전체 summary로만 알 수 있는 범위가 있음 |
| 알려진 문제 미반환 | COMPLETE + dependency findings=[] | “조회한 정확한 버전에서 알려진 취약점이 반환되지 않았습니다”와 안전 비보장 | COMPLETE는 지원 inventory 처리 완료일 뿐 전체 의존성 목록 검증 아님 |
| FP 제외 | 최종 목록에서 삭제; 채택 결과에 metadata | 카드 confidence/오탐 가능성/판단 근거 | 제외 전 매치 수/사유 집계는 API에서 복원 불가 |
| Java AST 파싱 실패/인덱싱 제한 | skipped/unparsed 파일 수 notice, 제한된 slice만 남음 | Semantic 기술 정보에 notice/생략 slice 수 | 실패 파일 목록·각 사유는 없음. 인덱싱 누락과 후보 validation 거부는 서로 다른 단계 |
| AI Semantic 미실행/실패 | 아래 status 표 | 미실행/분석 불가/실패와 “후보 없음은 안전 아님” | 기본 요약의 숫자만 읽으면 상세 notice를 놓칠 수 있음 |
| Semantic snapshot 저장 실패 | saved Review를 그대로 반환; semanticReview=null 가능 | 저장된 추가 검토 결과 없음 | 과거 미실행 이력과 저장 실패를 API에서 직접 구분하기 어려움 |
| 예기치 않은 예외 | GlobalExceptionHandler 500, 일반 오류 | 일반 오류 표시 | structured stage/reason code 없음. 저장 전 실패와 저장 후 보조 단계 실패를 구분해 조사 필요 |
| 재검사 실패 | 기존 Review 유지 | error와 기존 결과가 유지됨 | 이번 실패와 과거 결과를 새 성공 결과로 혼동하지 않는지 실제 평가에서 확인 |

Semantic status 의미:

| 값 | 의미 |
| --- | --- |
| NOT_REQUESTED | STANDARD 또는 template 모드 등에서 미실행 |
| UNAVAILABLE | parser/provider/request budget/문맥 예산 등의 조건 불충족 |
| NO_SUPPORTED_CONTEXT | 실제 provider 경로에 도달했으나 선택 가능한 Java endpoint 문맥 없음 |
| COMPLETED | 선택되어 전송된 slice의 출력 처리 완료; 생략 slice가 있어도 이 상태 가능 |
| PARTIAL | 일부 후보 근거 검증 거부, 유효 후보/기존 보조 근거는 남음 |
| FAILED | provider/응답/전체 validation 예외 |
| REJECTED | 제안 후보가 검증에서 거부되고 유효 후보/보조 근거가 없음 |
| snapshot null | 저장된 정보 없음. 미실행/실패/과거 이력 원인을 추정하지 않음 |

근거: [Error handler](../../src/main/java/com/securedeploy/global/error/GlobalExceptionHandler.java), [API client](../../frontend/src/api/securityReviewApi.ts), [ProjectWorkspace](../../frontend/src/components/ProjectWorkspace.tsx), [SCA UI](../../frontend/src/components/DependencySecuritySection.tsx), [Risk UI](../../frontend/src/components/RiskAssessmentSection.tsx), [Semantic UI](../../frontend/src/components/SemanticReviewSection.tsx), [SemanticSnapshotService](../../src/main/java/com/securedeploy/ai/semantic/SemanticSnapshotService.java), [GitHubSourceInfo](../../frontend/src/components/GitHubSourceInfo.tsx).

## 9. 오해를 막기 위한 평가 주의점과 개선 후보

아래는 향후 변경 제안이며 이번 작업에서는 구현하지 않는다.

| 우선 | 코드에서 확인한 현황 | 개선 후보와 평가 관점 |
| --- | --- | --- |
| 1 | collector가 미지원을 조용히 제외. comparison context의 분석 경로는 내부 저장되지만 상세 DTO에는 전체 파일/미지원 inventory가 없음. Risk coverage의 ruleEngine은 성공 시 COMPLETE 고정 | 언어·영역별 coverage와 미지원/제외/실패 이유 명시. JavaScript 설정만 읽은 Python 프로젝트를 전체 검사 완료로 보이지 않게 하기 |
| 2 | SCA COMPLETE는 인식한 manifest/component 범위. Maven BOM, Gradle catalog, 미지원 lock의 누락을 포괄적으로 설명하지 못함 | 인식했지만 해석하지 못한 선언과 미지원 구조/생태계를 구분. 의존성 0건과 분석 불가를 분리 |
| 3 | Rule 대부분이 행 패턴이며 FP 대상 밖 룰에도 confidence HIGH 부여. 일반적인 고정 업데이트 버전이나 sourceFiles를 수정 위치로 제시 | 실제 방어 코드/버전 선언/lock 출처를 대조. confidence를 확정성과 혼동하지 않도록 설명. 수정 버전은 advisory별 근거와 호환성을 유지 |
| 4 | 초기 실패는 Review가 남지 않음. error body는 timestamp/status/error/message만 있음 | credential 없는 시도 ID·실패 stage·coverage 기록 검토. 재현성과 미검사 상태 인식을 우선 |
| 5 | Semantic은 선택된 일부 문맥만 사용. skip 이유는 합산, 저장 실패는 null 가능. literal masking으로 중요한 문맥이 줄어들 수 있음 | 대상 slice와 생략 이유/저장 상태 명확화. 후보 0건을 안전 판정으로 사용하지 않기. 원하는 모델 결과에 맞춰 fixture를 바꾸지 않고 평가 |

`ReviewResultWorkspace`는 주요 결과를 Risk Assessment로 표시하고 참고 점수는 기술 정보로 분리한다. SCA/AI 미완료 경고도 존재한다. 남는 과제는 주의 문구의 부재가 아니라 **검사하지 못한 실제 범위를 특정하기 어렵다는 점**이다. `scannedFileCount`의 “N개 파일 검사”와 Risk의 `ruleEngine=COMPLETE`는 선택된 범위의 완료라는 한정이 필요하다.

`vulnerabilityCount`가 화면에서 “원본 룰 탐지 수”로 표시되어도 FP 처리 전 건수는 아니다. 기존 snapshot을 재계산하지 않고 기록하며 통합 Priority 건수, OSV advisory 건수, AI 후보 건수를 별도로 비교한다.

근거: [Result workspace](../../frontend/src/components/ReviewResultWorkspace.tsx), [ComparisonContextCollector](../../src/main/java/com/securedeploy/project/progress/ComparisonContextCollector.java), [Review DTO](../../src/main/java/com/securedeploy/review/dto/SecurityReviewResponse.java), [DependencyFindingCard](../../frontend/src/components/DependencyFindingCard.tsx), [Risk engine](../../src/main/java/com/securedeploy/risk/service/RiskPrioritizationEngine.java), [현재 Risk policy](../../src/main/java/com/securedeploy/risk/policy/DefaultRiskPolicy.java).

## 10. 평가 재현성과 이번 작업 경계

| 식별 정보 | 현재 코드의 정보 | 평가할 때 기록할 내용 |
| --- | --- | --- |
| SecureDeploy 버전 | 문서 상단 Git SHA | 실행 JAR와 HEAD 일치는 별도 확인. git clean만으로 실행 코드 일치를 증명할 수 없음 |
| Rule 전체 버전 | 독립된 공개 version field 없음 | Git SHA를 기준으로 사용 |
| comparison analyzer 버전 | `coverage-v1:` + rule/dependency/project-service class hash | 내부 context 값을 확보한 경우만 기록. SCA/AI 전체 코드를 포함하는 hash는 아님 |
| Risk | policy `risk-v1.2`, schema 3 | 실제 snapshot 값/threshold를 우선 |
| SCA | schema 1, analyzedAt | provider 정보·조회 시각·실패·cache·범위를 함께 기록 |
| Semantic | schema 1, prompt `semantic-v1`, provider/model/requestCount/usage | 실행한 경우만 기록. 후보 개수만으로 평가하지 않음 |
| GitHub source | default branch/full SHA/short SHA/commit timestamp/수집 시각 등 | API metadata의 tip SHA와 실제 수집된 Review source SHA를 혼동하지 않음 |

실제 5건 평가에서는 (1) 수집한 동일 SHA, (2) 중요 기능 2~3개의 입력부터 사용 위치까지 정적 대조, (3) 탐지 결과의 방어 처리와 반대 근거, (4) 의존성 선언 출처와 실제 수정 위치, (5) 미확인 사항과 다음 행동을 우선한다. 정답 집합이 없으면 전체 탐지율을 계산하지 않는다. 개선 전후 비교에서는 코드 변경과 DB/provider 갱신에 따른 차이도 분리한다.

이번 작업은 소스 조사와 문서 작성만 수행했다. 엔진·prompt·policy·migration·사용자 데이터·환경 설정은 변경하지 않았다. 실제 대상 repository 평가, 테스트 재실행, 브라우저 확인, 외부 호출, commit/push는 수행하지 않았다.
