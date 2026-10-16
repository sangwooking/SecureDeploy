# 비공개 실제 프로젝트 평가: urisai / runwhen

- 평가일: 2026-10-16 (Asia/Seoul).
- SecureDeploy: `cf17e2a499b0fe7a1215a2bea86eef3c25120d9b`, main. 제품 소스 변경 없음.
- 방법: 사용자가 연결된 GitHub 저장소 화면에서 각각 STANDARD 1회 실행. DB snapshot을 읽기 전용으로 확인하고 같은 SHA의 소스를 별도 정적 검토했다.
- 기준 문서: [지원 범위](../current-analysis-support.md), [평가 템플릿](../project-evaluation-template.md). 두 기존 문서는 그대로 보존했다. 그 문서의 a94170a 기준과 이번 cf17e2a 기준을 혼동하지 않는다.
- 상세: [urisai](2026-10-16-urisai.md), [runwhen](2026-10-16-runwhen.md).

## 1. 결과 요약

| 항목 | urisai | runwhen |
| --- | --- | --- |
| 분석 SHA | `cf896916119d0a166163391d15e70aa4a36dd953` | `7fc8dd309297fc33e8ea204f8d7903a31a7eb58a` |
| Review / Project | 69 / 38 | 68 / 37 |
| 기본 브랜치 / 수집 | main / GITHUB_APP / private | main / GITHUB_APP / private |
| 전체 정적 파일 / scanner 선택 | 46 / 18 | 44 / 28 |
| 정책 제외 / 미수집 파일 | 0 / 28 | 0 / 16 |
| Rule 원시 / FP 후 | 0 / 0 | 0 / 0 |
| SCA 상태 | COMPLETE | COMPLETE |
| 정확 버전 unique 조회 / 미확정 | 345 / 0 | 182 / 0 |
| 취약 package-version / advisory finding | 5 / 21 | 0 / 0 |
| 반드시 처리 / 직접 확인 / 수정 권장 / 참고 | 2 / 0 / 16 / 3 | 0 / 0 / 0 / 0 |
| 참고 점수 / Risk | 100 / BLOCKED | 100 / READY |
| Semantic | NOT_REQUESTED, requestCount=0 | NOT_REQUESTED, requestCount=0 |
| 수집 시작~저장 직전 분석 시각 | 11.794초 | 3.528초 |

시간은 source snapshot의 `analyzedAt - cloneStartedAt`이다. 사전 App 권한 확인, 최종 snapshot 처리 및 브라우저 전체 왕복 시간을 포함한 계측값은 아니다. 개별 HTTP 상태 코드는 브라우저 네트워크 기록을 수집하지 않아 미확인이다. 사용자 화면 완료 및 동일 SHA/결과의 DB 저장은 확인했다.

**핵심 판단:** urisai는 알려진 의존성 버전 문제를 찾았다. 그러나 21건 모두 `devDependencies`이고 실제 운영 도달 가능성은 확인하지 않았다. runwhen은 현재 지원 패턴과 조회한 버전에서 미발견이지, 서버 로직 전체가 안전하다는 검증 결과가 아니다. 두 결과는 전체 탐지율이나 프로젝트 전체의 취약점 정답 목록이 아니다.

## 2. 실행 기준과 보존

- PID 25652의 실행 JAR과 현재 build class/resource 386개 항목이 일치함을 확인했다. 제품 작업 트리는 clean이었고 기존 평가 문서만 untracked였다. 서버 재시작은 하지 않았다.
- AI provider는 환경변수와 CLI 모두 template. STANDARD 저장값과 Semantic 미실행을 확인했다. 수동 AI 기능도 요청하지 않았다.
- Rule Engine 27개 구현 클래스. Risk `risk-v1.2`, Risk schema 3, SCA schema 1. Rule 전용 version 필드는 없으므로 소스 commit으로 식별한다.
- GitHub 60초/200MB/12요청, 분석 파일 32MB/합계128MB/500,000줄/50,000개, SCA 500 unique query/100 advisory 한도는 현재 설정 기준이다. 관련 범위 초과·파싱 실패·source limitation은 이번 결과에 없었다.
- GitHub App 사용자 접근과 설치 범위 검증을 통과한 실제 수집이며 기존 사용자 CLI로도 두 저장소의 `pull=true`를 확인했다. 별도 정적 수집의 SHA는 저장된 분석 SHA와 일치한다.
- source/risk/SCA/remediation/semantic/comparison snapshot 저장 확인. 두 비교 snapshot은 첫 분석이므로 NO_BASELINE. 평가 Review는 삭제하지 않는다.

## 3. 공통 지원 범위와 의미

| 영역 | 실제 지원 | 평가에서 발견한 한계 |
| --- | --- | --- |
| React/JS/TS | B: 문자열·정규식 패턴 | 서버 Worker/Pages Function도 TYPESCRIPT로 읽지만 인증/인가/CSRF/데이터 흐름 구조 분석은 없음 |
| npm package.json + v3 package-lock | C: 구조 파싱 및 EXACT OSV 조회 | 설치·배포된 graph와 다름. 부모 dependency chain 및 lock JSON 위치를 결과에 보존하지 않음 |
| Cloudflare 배포 | D: wrangler.jsonc, _headers, _routes.json 미수집 | 실제 두 프로젝트가 사용하는 배포·보안 헤더 경계를 검사하지 않음 |
| Python / .mjs / SQL migration | D | runwhen의 Python 보조 스크립트, urisai의 배포 mjs와 D1 trigger는 분석 밖 |
| Java/Spring AST | 이번 저장소에는 Java 없음 | AI_ENHANCED로 바꾸기만 해도 TS endpoint Semantic 분석이 생기는 것은 아님 |

두 저장소에 requirements/pyproject/Pipfile/poetry, Maven/Gradle, Docker/K8s/Nginx/GitHub Actions 파일은 없었다. 없음과 지원하지 않음을 구분한다. 테스트 파일은 분석 수에 포함됐다. README/이미지/CSS 등 목적상 미수집 파일과 보안상 중요한 미지원 설정을 같은 위험으로 취급하지 않는다.

## 4. 탐지·오탐·미탐 평가

- urisai: 5개 package-version과 21개 advisory의 lockfile 존재를 모두 확인했다. 같은 advisory가 vitest와 @vitest/mocker에 각각 적용되어 distinct advisory는 20개다. 무조건 중복 제거할 오류는 아니지만 해결 작업 단위로 묶을 여지가 있다.
- 모든 urisai finding은 개발 의존성이다. `CRITICAL -> BLOCKING`은 현재 정책대로 동작했으며 버전 파싱 오탐은 아니다. 운영 웹 공격이 가능한 것으로 단정한다면 영향 평가 과장이 된다. 개발 환경·CI 공급망 위험 역시 무조건 제외하면 안 된다.
- Rule 매치 0건은 실제 후처리 제외 때문이 아니다. 외부 호출 없는 현재 scanner/27개 rule/FP의 오프라인 재대조도 0→0이었다. FP 정확도 또는 recall을 이 표본만으로 입증할 수 없다.
- urisai의 OIDC/CSRF/파라미터 바인딩/공간 권한 검사는 방어 코드가 존재했다. 임의로 인증 우회·SQL injection·XSS를 미탐으로 판정하지 않았다.
- runwhen의 upstream 호출은 고정 HTTPS host와 지역 allowlist를 사용한다. SSRF가 확인된 것은 아니다. 전역 quota/동시 요청 합치기는 코드에서 확인되지 않아 비용·가용성 검토 후보로 남겼다.
- AI Semantic은 Java endpoint 전용이다. 현재 두 저장소에서 AI 강화 모드만 켜는 해결책을 권하지 않는다. 향후 TS 서버 entry/sink/guard 문맥을 먼저 수집해야 보조 분석의 근거가 생긴다.

## 5. 사용자 안내 평가: 엔진 문제와 UI 문제

1. 엔진 정보 부족: 미수집 파일 목록·언어별 검사 수준이 snapshot에 없다. `ruleEngine=COMPLETE`는 실행 완료를 뜻하지만 TS 서버 인가 분석 완료로 오해할 수 있다.
2. UI에서 확보 정보를 충분히 쓰지 못함: dependencyFacts에 direct/scopes가 있지만 DependencyFindingCard는 이를 보여주지 않는다. 개발 전용·직접/간접 여부를 앞에서 설명할 수 있다.
3. 엔진+UI: 모든 dependency의 sourceFile이 package-lock.json이고 line=0이다. UI의 '수정할 파일'은 실제로는 '버전을 발견한 파일'이며, 수정해야 할 package.json의 vitest/miniflare 선언과 구분되지 않는다.
4. 잘된 부분: 현재 버전·advisory별 수정 버전·업데이트 후 테스트/재검사 안내, 미발견/READY의 안전 비보장 문구가 존재한다. 임의의 단일 '모두 안전한 버전'을 만들지는 않는다.
5. 실행 확인 범위: 사용자에게 상단 실제 결과 수를 확인받았다. 각 카드 펼침과 모바일 시인성은 이번에는 직접 브라우저로 검증하지 않았으며, 세부 UI 평가는 컴포넌트 소스 기준이다.

## 6. Security Core Hardening 제안 순서

| 순서 | 제안 | 이번 근거 | 다음 검증 기준 |
| --- | --- | --- | --- |
| 1 | Coverage ledger와 판단 한계 노출 | runwhen READY인데 TS 서버 구조/Cloudflare 설정은 미지원 | 파일·영역마다 지원/부분/미지원/제외/실패를 저장하고 배포 요약에 설명. 미지원 파일이 있다는 이유만으로 모두 차단하는 단순 정책은 지양 |
| 2 | dependency 출처·부모 경로·환경 문맥 | urisai 21건 모두 dev, tinypool 2건 BLOCKING | lock 설치 위치와 package.json 부모 선언 연결, build/test/runtime/미확인 구분. dev라는 이유로 일괄 안전 처리 금지 |
| 3 | TS 서버의 제한적 구조·흐름 분석 | Worker 인증/CSRF/D1, Pages 입력→HTTP 흐름이 현재 패턴 밖 | entry point와 직접 호출, sink, 명시적 guard, 정적 host/parameter binding 근거부터 검증. 전체 reachability를 약속하지 않음 |
| 4 | 배포 설정과 스크립트 coverage | wrangler/_headers/_routes/.mjs/SQL이 누락 | 파일 인식과 미지원 안내를 먼저 만들고 구체 검사 범위를 별도 합의 |
| 5 | 수정 작업 중심 안내·회귀 corpus | 동일 Vitest advisory 2패키지, 다수 Undici advisory, 버전 위치 혼동 | 원본 finding 보존 + 상위 dependency별 작업 묶음. 이번 SHA/Review를 기준으로 과잉 경고와 누락을 함께 비교 |

지금은 위 개선을 구현하지 않았다. 이 작업의 역할은 '탐지 개수 증가'가 아니라 배포 판단이 어떤 근거와 공백에 기반하는지 고정해 다음 개선의 평가 기준을 만드는 것이다.

## 7. 외부 호출과 미실행 검증

- 실제 외부 호출: 두 STANDARD의 GitHub App 권한 확인/읽기 전용 수집/토큰 회수, 기존 OSV batch/advisory 조회, urisai CVE의 EPSS/KEV 조회. 개별 HTTP 요청 총수는 현재 snapshot에 없어 미확인.
- 별도 정적 수집: 저장소당 metadata, main ref, 고정 SHA tarball의 3회 CLI API 작업. tarball redirect의 HTTP hop 수는 별도 미계측. 토큰은 CLI 내부에서만 사용했다.
- 실제 App 수집 SHA와 별도 코드 SHA 일치. 수집 시 symlink/submodule/LFS 0, limitations 빈 배열.
- 대상 npm/pip/Gradle 설치·빌드·테스트·스크립트·Docker/CI 실행, 운영 endpoint 접근·공격, credential 유효성 확인은 모두 하지 않았다. 저장소 README의 실행 지시는 데이터로만 읽었다.
- 새로운 OpenAI 호출, 엔진/Rule/Risk 변경, DB schema/migration 변경, 기존 사용자 데이터 수정/삭제, commit/push 없음.
- 권한 또는 승인 거부 없음. 평가 시간대의 안전한 단계 로그에서 설치 토큰 발급 HTTP201 두 번과 회수 HTTP204 두 번을 확인했다. 이것은 GitHub 전체 HTTP 요청 수를 뜻하지 않는다.

## 8. 최종 보관 점검

- 평가 Review: 68(runwhen), 69(urisai), 기존 로그인 소유 계정에 보존.
- 저장된 SHA/스캔 수/모드와 정적 대조 inventory의 일치, 21개 advisory 표의 ID/fixedVersions 일치를 확인했다.
- 백엔드 임시 GitHub 수집 폴더 0개. 별도 검토용 두 저장소 소스, 임시 DB snapshot 사본, 평가 helper/runtime도 정리했다. 실행 중인 개발 서버와 사용자 비밀 설정은 유지했다.
- 문서의 토큰/키/개인 이메일/개인 로컬 경로 패턴 검사와 공백 검사를 통과했다. 원본 소스·credential·원문 로그는 문서에 첨부하지 않았다.
- 최종 제품 tracked diff 없음. 기존 `docs/evaluation/` 문서 두 개와 이번 결과 문서 세 개만 untracked. commit/push하지 않았다.

## Security Core Hardening 1차 대조 메모 (2026-10-16)

앞부분의 평가는 `cf17e2a` 당시 baseline이다. 기존 Review 68/69 및 원본 snapshot은 변경하지 않았다.
이번 대조는 같은 두 저장소 SHA의 package.json/package-lock.json과 파일 목록만 다시 읽고, 저장된 OSV/EPSS/KEV 응답을 고정해 로컬에서 수행했다. 외부 취약점 DB 재조회·OpenAI·대상 코드 실행은 없었다.
urisai: 375개 위치/21개 advisory/2 BLOCKING/16 SHOULD_FIX/3 INFORMATIONAL/BLOCKED 불변. vitest → tinypool 및 miniflare → sharp/undici의 개발 선언 경로와 package.json 수정 검토 위치가 추가로 확인됐다. 실행 도달성은 미확인이다.
runwhen: 182개 위치/0 advisory/READY 불변. 새 범위 기록으로 urisai 46개 중 18개 패턴 입력·28개 미지원, runwhen 44개 중 28개 입력·16개 미지원이 구분된다. 이는 의미 분석 또는 안전성 보증이 아니다.
차이는 신규 경로·범위 근거이며, 취약점 DB 갱신 효과는 아니다. 전체 실프로젝트 재분석은 수행하지 않았다. 합성 ZIP/GitHub 및 snapshot/API 회귀 테스트로 공통 파이프라인을 별도 검증했다.
