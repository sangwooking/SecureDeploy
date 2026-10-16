# 읽기 전용 GitHub App 연결

## 현재 상태와 적용 경계

- 기본값은 `GITHUB_APP_ENABLED=false`. ZIP과 익명 공개 GitHub 분석은 기존 경로를 유지한다.
- GitHub App을 사용하는 저장소도 기존 Rule Engine / False Positive / SCA / Threat Intelligence / Risk / 해결 가이드 / Semantic / Progress 파이프라인으로 처리한다.
- 실제 GitHub App 사용자 연결과 작은 비공개 fixture의 STANDARD 첫 분석·재검사, 설치 일시 중지 후 접근 차단, History/Before-After 표시를 확인했다. 검증 범위와 남은 운영 한계는 아래 기록에서 구분한다.
- `docs/evaluation/`의 기존 문서 두 개는 이번 작업과 별개로 유지한다.

## 1. GitHub App 등록 (사용자 작업)

GitHub Settings → Developer settings → GitHub Apps → New GitHub App에서 다음과 같이 등록한다.

| 항목 | 설정 |
| --- | --- |
| App name | 본인 계정에서 사용할 고유 이름 |
| Homepage URL | SecureDeploy 프론트엔드 주소 |
| Callback URL | 개발: `http://localhost:5173/`, 운영: 실제 HTTPS 프론트엔드 루트 URL |
| Repository permissions | **Contents: Read-only**, **Metadata: Read-only** |
| Account / Organization permissions | 추가 권한 없음 |
| Webhook | 현재 미사용, Active 해제 |
| User access tokens | 만료되는 사용자 토큰 활성화 |
| Request user authorization during installation | 해제. SecureDeploy의 state/PKCE 시작 경로로 인증 |
| Device flow | 미사용 |

Contents Write, Issues, Pull requests, Administration, Actions/Workflows 등의 권한은 요청하지 않는다.
실제 설치에 불필요한 권한이 있으면 서버가 해당 설치 사용을 거부한다.
설치 화면에서는 **Only select repositories**를 선택하고 분석할 저장소만 승인한다.
조직의 설치 승인 또는 SAML SSO가 필요한 경우 조직 관리자의 승인/활성 SSO 세션이 필요할 수 있다.
설치만으로 연결이 완료되지는 않는다. SecureDeploy 로그인 후 계정의 **GitHub 연결**을 별도로 진행한다.

## 2. 서버 비밀 설정

채팅, 소스코드, frontend 환경변수(`VITE_*`), Git, 실행 명령 인자에 비밀값을 넣지 않는다.
운영에서는 Secret Manager 또는 접근 제한된 런타임 secret 파일/환경 주입을 사용한다.

| 서버 환경변수 | 내용 |
| --- | --- |
| `GITHUB_APP_ENABLED` | 설정과 migration 완료 후 `true` |
| `GITHUB_APP_ID` | GitHub App의 숫자 App ID |
| `GITHUB_APP_CLIENT_ID` | GitHub App의 Client ID (App ID와 다름) |
| `GITHUB_APP_CLIENT_SECRET` | GitHub에서 생성한 Client Secret |
| `GITHUB_APP_SLUG` | App 설치 URL의 slug |
| `GITHUB_APP_PRIVATE_KEY_FILE` | 저장소 밖에 보관한 PKCS#8 RSA PEM 파일의 절대 경로 |
| `GITHUB_TOKEN_ENCRYPTION_KEY` | 별도 생성한 32바이트 무작위 키를 Base64로 인코딩한 값 |
| `GITHUB_APP_CALLBACK_URL` | 등록한 Callback URL과 정확히 같은 URL (query/hash 없음) |

GitHub에서 내려받은 PKCS#1 키는 서버 밖 보안 경로에서 PKCS#8로 변환한다.
다음 명령의 경로는 예시이며, 저장소 내부에 키를 만들지 않는다.

```sh
umask 077
openssl pkcs8 -topk8 -nocrypt -in /secure/path/github-app-original.pem -out /secure/path/github-app-pkcs8.pem
chmod 600 /secure/path/github-app-pkcs8.pem
```

암호화 키는 JWT_SECRET, GitHub Private Key, Client Secret과 서로 다른 키여야 한다.
터미널 출력이나 셸 기록으로 유출하지 말고 Secret Manager에서 생성/등록한다.
암호화 키를 바꾸면 기존 연결 토큰을 해독할 수 없으므로 연결 해제 및 재연결이 필요하다.
설정 변경 후 백엔드를 재시작한다. 기존 DB 설정/JWT_SECRET은 그대로 유지한다.
`.env`, `*.pem`, `*.key`는 Git ignore 대상이지만 ignore만을 비밀 관리 수단으로 삼지 않는다.

## 3. DB migration

기존 프로젝트는 migration runner 없이 SQL 파일을 수동 적용하는 구조이다.
적용 파일: `src/main/resources/db/postgresql/20261016_github_app_read_only.sql`.

- `github_connections`: 사용자당 연결 하나. GitHub user ID/login, AES-256-GCM 암호문, 만료 시각, 연결 시각.
- `projects`: nullable `github_repository_id`, `github_installation_id`, `private_repository` 추가.
- `(user_id, github_repository_id)` unique partial index. 기존 URL 기반 프로젝트는 null을 유지한다.
- 기존 Review/Vulnerability/SCA 및 source metadata JSON은 수정하지 않는다.
- 기존 snapshot에 새 필드가 없어도 역직렬화할 수 있다. 새 snapshot은 repo/installation ID, visibility, `GITHUB_APP` 수집 방식을 포함한다.

백업 및 대상 DB 확인 후 기존 인증 설정(`PGSERVICE`, 비밀 파일 등)을 사용한다.

```sh
psql -X -v ON_ERROR_STOP=1 -f src/main/resources/db/postgresql/20261016_github_app_read_only.sql
```

DDL은 반복 적용 가능하지만 올바른 대상 DB/스키마인지 운영자가 먼저 확인해야 한다.
Hibernate `ddl-auto=update`만으로 unique index 적용을 대신하지 않는다.
별도 검증 스크립트 `src/test/resources/github/app-migration-check.sql`은 caller가 지정한 새 임시 스키마에만 가짜 데이터를 만들고 SQL을 두 번 적용한 뒤 스키마를 제거한다.
이 검증은 실제 개발 DB에 migration을 영구 적용한 것과 다르다.

## 4. 인증과 권한 경계

1. 로그인 Bearer 요청으로 `POST /api/github/connection/authorize` 호출.
2. 서버에서 256-bit random state/PKCE verifier 생성. state는 사용자 ID, 시작한 JWT의 SHA-256, 5분 만료와 연결된다. 같은 사용자의 새 요청은 이전 state를 무효화한다.
3. GitHub의 공식 App 사용자 authorization code + PKCE S256 흐름. 추가 scope는 요청하지 않는다.
4. 프론트 callback은 URL의 code/state를 즉시 제거하고, 현재 SecureDeploy Bearer로 `POST /api/github/connection/callback`에 전달한다. 브라우저 저장소에는 GitHub 토큰·code·state를 저장하지 않는다.
5. 서버가 사용자·세션·state·만료·일회성을 검사한 뒤 code를 교환한다. GitHub `/user`로 계정 ID를 확인한다. 기존 연결과 다른 GitHub 계정이면 명시적 연결 해제 전에는 교체하지 않는다.
6. 사용자 access token만 AES-256-GCM으로 암호화해 저장한다. nonce는 매번 새로 생성하고 사용자 ID를 AAD로 사용한다. refresh token은 보관하지 않는다. 최대 8시간 후 재연결한다.
7. 사용자 token으로 `/user/installations/{id}/repositories`를 조회해 **사용자 접근과 설치 범위의 교집합**을 확인한다. `permissions.pull`도 확인한다. 설치는 설정한 App ID, 미정지 상태, 허용된 읽기 전용 권한이어야 한다.
8. 선택 ID를 서버에서 재확인한 뒤 `repository_ids: [선택 ID]`, contents/metadata read 권한으로 installation token을 생성한다. 응답의 수명·권한·저장소 범위도 검사한다.
9. 토큰은 canonical GitHub 저장소의 `info/refs` / `git-upload-pack` 요청 헤더로만 전달한다. redirect, 쿠키, 프록시, 임의 Authorization 헤더, receive-pack, 다른 호스트/저장소는 허용하지 않는다.
10. 소스 수집 직후 사용자 권한을 다시 확인한다. finally에서 installation token 회수를 시도하고 메모리 credential을 닫는다. 회수 실패 시 GitHub의 1시간 이내 만료가 최종 방어다.
11. 공통 파이프라인 종료 또는 실패 시 임시 bare Git와 소스 디렉터리를 정리한다. 저장소 build/script, hooks, CI는 실행하지 않는다.

JGit 수집의 기존 제한(시간·요청 수·전송량·파일 수·해제/분석 크기), symlink/submodule/LFS 제외 정책을 유지한다.
App API는 고정 HTTPS GitHub endpoint만 사용하고 redirect를 따르지 않는다. 요청/응답은 20초·2MiB 제한이다.
설치·저장소 목록은 페이지당 100개, 최대 10페이지다. 범위를 넘으면 접근 확인을 완료한 것으로 처리하지 않는다.
state는 서버 메모리에 최대 1,000개를 보관한다. 서버 재시작/다중 인스턴스 전환 시 다시 연결해야 한다. 다중 인스턴스 배포 전에는 state의 공유 일회성 저장소가 필요하다.

## 5. API / 화면

- `GET /api/github/connection`: 비밀값 없는 현재 사용자 연결 상태.
- `POST /api/github/connection/authorize`: 로그인 세션에 묶인 authorization URL.
- `POST /api/github/connection/callback`: code/state 교환. 공개 callback API가 아니며 Bearer 인증 필수.
- `DELETE /api/github/connection`: 서버 연결 삭제, 사용자 token 회수 시도. 실패하면 GitHub 설정에서 추가 해제를 안내.
- `GET /api/github/installations?page=1`: 접근 가능한 읽기 전용 설치.
- `GET /api/github/installations/{installationId}/repositories?page=1`: 사용자와 설치가 모두 승인한 저장소.
- `POST /api/reviews/github/connected`: `{installationId, repositoryId, scanMode}`.
- `POST /api/projects/{projectId}/reviews/github/connected`: 같은 repository ID의 소유 프로젝트에 재검사.
- 기존 `/api/projects/{projectId}/reviews/github`도 App 연결 프로젝트이면 저장된 ID로 인증 경로를 사용한다. 입력 URL로 다른 비공개 저장소를 조회하지 않는다.

계정에서 연결/해제 → 새 프로젝트의 연결된 GitHub 저장소 → 설치 계정/저장소 선택 → STANDARD/AI 선택 → 분석.
이력·Workspace의 공개/비공개 정보는 마지막 분석 당시 상태이며 실시간 GitHub 상태로 오해하지 않는다.
GitHub 연결 해제는 설치 제거와 다르다. GitHub에서 App 설치 범위도 별도로 축소/해제할 수 있다.
동일 GitHub 계정을 여러 SecureDeploy 사용자에게 연결해도 프로젝트/이력 소유권은 별개이다. 사용자 간 공유나 팀 RBAC를 만들지 않는다.
기존 익명 URL 프로젝트와 App 연결 프로젝트는 자동 병합하지 않는다. App 연결 프로젝트는 사용자 + repository ID로 식별한다.

## 6. 비공개 데이터 보관과 외부 전송

- 원본 전체 소스는 분석 중 임시 저장 후 삭제한다. 토큰을 source_metadata/Review 응답/오류/로그/Git remote URL에 넣지 않는다.
- findings, 마스킹 evidence, 제한된 snippet, source metadata, risk/SCA/AI/progress snapshot은 기존 Review 정책으로 DB에 남는다. 비공개 코드 일부가 포함될 수 있어 DB/백업 암호화와 운영 접근 통제가 필요하다.
- 사용자 토큰 암호문은 재연결 시 교체, 연결 해제 시 삭제한다. 만료 후 자동 refresh하지 않으며 서버에서는 사용을 거부한다. 만료된 암호문 정기 제거 작업 및 백업의 보관 기간은 별도 운영 정책이다.
- GitHub 권한 해제 후에도 SecureDeploy 소유자의 과거 snapshot은 유지한다. 원본 GitHub 접근 권한과 저장된 Review 열람 권한은 다른 개념이다. 신규 수집은 반드시 재확인한다.
- STANDARD에서도 패키지 이름·생태계·확정 버전이 OSV에 전달될 수 있다. EPSS/KEV는 공개 CVE 식별자/공개 feed를 사용한다. 코드 전체를 보내지는 않지만 비공개 패키지명이 외부로 전달될 수 있으므로 UI에서 안내한다.
- AI_ENHANCED는 별도 명시 선택. 선별·마스킹된 코드/evidence 등이 외부 AI로 전송될 수 있으며 마스킹은 완전한 비밀 탐지 보장이 아니다. 기존 수동 AI 기능도 사용자가 요청할 때만 실행된다.
- 로컬 연결 JWT의 기존 localStorage 정책은 변경하지 않았다. XSS와 브라우저 확장으로부터의 보호는 여전히 중요하다.
- reverse proxy/access log에는 query string, Authorization, OAuth callback body를 기록하지 않는다. 운영 callback은 HTTPS로 제공하고 프론트 Referrer-Policy를 `no-referrer`로 유지한다.

## 7. 실제 E2E 승인 이후 확인할 항목

1. migration 적용과 서버 재시작, App 권한 read-only 및 선택 저장소 승인 확인.
2. 실제 본인 계정 연결, 승인된 작은 비공개 테스트 저장소 한 개만 선택.
3. STANDARD 1회, 실제 credential/개인정보 없는 fixture만 분석. OpenAI 호출 금지.
4. GitHub repo ID/default branch/full SHA, Review/History/Workspace metadata, 소스 cleanup 확인.
5. 권한 해제 후 재검사 실패 및 기존 snapshot 불변 확인. 불필요한 반복 외부 요청 금지.
6. 최종 비밀·산출물 점검 후에만 milestone commit/push.

## 8. OAuth 오류 구분

- token 교환은 HTTP 200이어도 OAuth 오류 JSON을 반환할 수 있다. `incorrect_client_credentials`는 App의 Client ID/Client Secret 설정 문제이며 사용자 토큰 만료로 안내하지 않는다.
- 사용자는 동일 App에서 발급한 Client ID와 Client Secret을 로컬 비밀 설정에서 교체하고 서버를 재시작한다. App Private Key, JWT secret, 토큰 암호화 키와 DB는 유지한다. 비밀값은 채팅이나 로그에 기록하지 않는다.
- 만료/재사용된 authorization code, 저장된 사용자 인증 만료, 설치 접근 거부, rate limit, 일시적인 통신 실패를 구분한다. 새 연결은 SecureDeploy에서 시작해 state/PKCE를 다시 발급한다.
- 로그에는 작업 단계, HTTP 상태, 허용 목록의 오류 종류만 남긴다. 요청/응답 원문, OAuth code/state/verifier, credential, Authorization 헤더를 기록하지 않는다.

## 로컬 검증 기록 (2026-10-16)

- Backend 전체: 298개 중 294개 통과, 실제 외부 smoke 4개 명시적 비활성화. 실패 0.
- Frontend: 63개 통과, TypeScript/Vite build 성공.
- Playwright Mock: 비공개 연결/선택/권한 해제, 기존 공개 GitHub, ZIP 업로드, Workspace 사용자 격리 각각 1440/390/320px에서 통과.
- PostgreSQL: 별도 임시 스키마 검증 후 개발 DB에도 migration을 영구 적용하고 반복 적용 안전성을 확인했다. 기존 사용자/Project/Review/Vulnerability/SCA 데이터를 보존했다.
- 실제 OAuth: callback의 로그인 JWT/state 검사 이후 code 교환에서 발생한 `incorrect_client_credentials`를 확인했다. 사용자가 로컬 Client ID/Client Secret을 바로잡고 서버를 재시작한 뒤 연결 및 승인 저장소 표시가 성공했다. 기존 Private Key/JWT secret/AES 키를 유지했다.
- 실제 비공개 STANDARD 분석: 테스트 설정 두 파일의 첫 분석에서 6건(점수 44), 수정 후 같은 Project 재검사에서 0건(점수 100)을 저장했다. source snapshot의 `GITHUB_APP`, 비공개 여부, main branch, 각각의 full commit SHA를 확인했다.
- 비교 snapshot: 기존 분석을 기준으로 해결 6건, 신규/지속 0건을 저장했다. 이 설정 fixture에는 의존성 manifest가 없어 SCA는 `NO_MANIFEST`, 비교는 `PARTIAL`, 최종 Risk Assessment는 두 분석 모두 `REVIEW_REQUIRED`다. 0건 또는 점수 100을 전체 프로젝트의 안전 보장으로 해석하지 않는다.
- 테스트 저장소의 두 커밋은 사용자의 명시적 승인 아래 별도 사용자 CLI 권한으로 반영했다. GitHub App은 Contents/Metadata Read-only를 유지했고 원본을 쓰거나 PR을 생성하지 않았다. 기존 README를 보존하고 실제 credential을 사용하지 않았다.
- 실제 브라우저 사용자 확인: 첫 분석 우선순위는 반드시 처리 0 / 직접 확인 2 / 수정 권장 5였다. 재검사 History/Before-After에서 두 분석과 해결 6건이 표시되고, 직접 확인은 1건으로 줄었다. 나머지 1건은 의존성 분석 범위 부족 안내이며 신규 취약점이 아니다.
- 실제 설치 일시 중지 후 같은 프로젝트의 재검사는 권한 오류로 차단됐다. 기존 History 두 건과 변화 보기는 보존됐으며 사용자가 Unsuspend 복구를 완료했다. 추가 실제 분석은 반복하지 않았다.
- 두 정상 수집의 설치 토큰 회수는 HTTP 204로 성공했고 분석용 임시 GitHub 소스 폴더는 0개였다. 사용자 접근 권한만 제거하거나 계정 연결을 해제하는 경로, 다른 사용자 차단, 인증 만료는 Mock/자동 테스트 범위이며 모두 실제 GitHub에서 반복 검증한 것은 아니다.
- 실제 OpenAI 호출 없음. 두 분석은 STANDARD이며 semantic request count는 0이다. 사용자 요청으로 생성한 평가 Review는 삭제하지 않는다.
- 최종 비밀정보/산출물 점검 후 milestone으로 정리한다. 기존 `docs/evaluation/` 문서 두 개는 이 milestone에 포함하지 않는다.

## 공식 참고 자료

- [GitHub App 사용자 인증 및 PKCE](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
- [사용자 접근 가능한 설치/저장소 API](https://docs.github.com/en/rest/apps/installations)
- [저장소로 제한된 installation token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [GitHub App 보안 권장사항](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app)
