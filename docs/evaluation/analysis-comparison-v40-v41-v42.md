# #34-C: v40 / v41 / v42 실제 앱 비교

## 판정

**새 미사용 앱 3개에서는 분석 연결·구조 Finding 증가를 관찰하지 못했다.**
v41·v42의 개발용 통제 개선은 재현됐지만, 이번 표본에서 실전 일반화 성과는 입증되지 않았다.
엔진·Rule·Risk·API·DB·UI는 변경하지 않았다. 제품 전체 Precision/Recall은 계산할 수 없다.

기준은 v40 `032fc53`, v41 `4dac021`, v42 `d58f69b`다. 각 버전의 별도 worktree에서 동일한
Java 평가기·수집본·선택기·Rule/FPR/Risk 코드를 확인하고 격리 H2에서 앱별 2회 분석했다.
후처리 검증 도구 확정 후 별도 결과 경로로 한 배치를 더 수행했고, 시간·heap·평가시각을 제외한 결과가 일치했다.
최초 결과는 덮어쓰지 않았다. SCA 외부 조회·AI·대상 설치/빌드/실행·운영 요청은 수행하지 않았다.
환경은 macOS arm64, Node 26.0.0, OpenJDK 17.0.19, 분석 파서 TypeScript 6.0.3이다.
세 Worker의 기본 한도를 AST로 대조했다: 100파일, 파일당 100000자·합계 1000000자, 깊이 3,
100000 step, 200000 AST node, 함수 500, 결과 200, 내부 시간 5000ms로 모두 같다.

## 대상 고정

| 앱 | 고정 SHA | 라이선스 / 사용 이력 |
|---|---|---|
| [Papermark](https://github.com/papermark/papermark) | `ed19717ec02a1ac79aecf5569159aa9d2d869312` | [root LICENSE](https://github.com/papermark/papermark/blob/ed19717ec02a1ac79aecf5569159aa9d2d869312/LICENSE)의 AGPLv3 범위. 상용 `ee`, `app/(ee)` 제외. 기존 소스 평가 이력 미발견 |
| [Cloudflare Auth Kit](https://github.com/democra-ai/cloudflare-auth-kit) | `9638653fe71af7042ddcf838141ed9877d7c784c` | MIT. 기존 소스 평가 이력 미발견 |
| [OpenStarterKit](https://github.com/openstarterkit/nextjs-saas-starter-kit) | `30dfcc4d590fa37ff08357479edb9ccb1024d33a` | MIT. 기존 소스 평가 이력 미발견 |

결과 확인 전에 4개 후보 중 3개를 고정했다. gothinkster/node-express-realworld-example-app
`30b68e1e881462b2f4164ea09ab4c4f5699c7b0b`은 root 라이선스 문서 부재로 제외했다.
이 저장소는 과거에도 메타데이터 후보였지만 수집·분석 대상으로 선정되지는 않았다.
새 3개는 Grade C이며 독립 연구자 평가나 보안 정답이 있는 Holdout이 아니다. 이제 모두 관찰된 자료다.
고정한 전체 파일 목록·SHA256·누락 사유·원본 결과 해시는 [JSON](analysis-comparison-v40-v41-v42.json)에 있다.
외부 원본·로그·원시 평가 결과는 Git 외부에만 보관했다.

## 전체 비교

| 항목 | v40 | v41 | v42 | 해석 |
|---|---:|---:|---:|---|
| 새 앱 / 파싱 파일 | 3 / 218 | 3 / 218 | 3 / 218 | 파싱은 보안 검사 완료가 아님 |
| 선택 파일의 정적 import/export/require 구문 참조 | 1299 | 1299 | 1299 | 보조 AST 인벤토리. 연결 성공 수가 아님 |
| 실제 연결 모듈 / 호출 관계 / 인수 전달 / 반환 연결 총수 | N/A | N/A | N/A | 고정 Worker가 전체 edge 계수를 제공하지 않음 |
| 등록 진입점 / 도달 함수 | 54 / 78 | 54 / 78 | 54 / 78 | HTTP와 Server Function 등록 합계. 런타임 실행 보증 아님 |
| 정적 Next wrapper 연결 | 0 | 0 | 0 | 지원하는 named pure-factory 형태가 이번 선택 입력에 없음 |
| HIGH Source→Sink 후보 / 최종 구조 Finding | 0 / 0 | 0 / 0 | 0 / 0 | 미검사·UNKNOWN을 정상으로 계산하지 않음 |
| 부분적인 요청 Source→파일 API 관찰 | 1 | 1 | 1 | UNRESOLVED_RESOURCE. 취약점 TP 아님 |
| 기존 Rule 경고 | 22 | 22 | 22 | 위치·Rule·Score·Risk 동일. 모두 실제 취약점이라는 뜻 아님 |
| 검증된 신규 실앱 TP | 0 | 0 | 0 | 실제 취약·수정 정답 쌍 없음 |
| 전체 TP/FP/FN/TN·Precision/Recall | N/A | N/A | N/A | 프로젝트 정답과 검사 가능한 전체 경로 분모가 없음 |

### Papermark

Next `^14.2.35`, React `^18.3.1`, Prisma `6.5.0`. 1767개 발견 파일 중 텍스트 1533개 보관.
189개 상용 범위 파일, 링크·바이너리·대용량 파일 등을 명시적으로 제외했다.

| 항목 | v40 | v41 | v42 | 평가 |
|---|---:|---:|---:|---|
| TS 후보 / 제출·파싱 / 미제출 | 1195 / 100 / 1095 | 1195 / 100 / 1095 | 1195 / 100 / 1095 | 한도 유지. 누락 상세 995개는 개별 Worker descriptor에도 없음 |
| 정적 모듈 참조 / 연결 모듈 | 781 / N/A | 781 / N/A | 781 / N/A | 참조와 연결 성공 구분 |
| 등록 진입점 / 도달 함수 | 17 / 14 | 17 / 14 | 17 / 14 | 등록된 handler 파일 4개는 도달 함수 0 |
| 인수·반환 총계 / wrapper | N/A / 0 | N/A / 0 | N/A / 0 | 전체 그래프 미노출 |
| HTTP 관찰 / 구조 Finding / Rule 경고 | 2 / 0 / 8 | 2 / 0 / 8 | 2 / 0 / 8 | HTTP 두 건 모두 목적지 미확인·입력 trace 없음 |
| 시간, ms (2회) | 1465, 1063 | 1435, 1070 | 1440, 1087 | JVM/Gradle 시작 시간 제외 |
| 부모 JVM heap 샘플, MiB | 94.4, 135.8 | 111.9, 128.3 | 85.3, 197.8 | Worker RSS·최대 heap 아님 |
| Coverage / Score / Risk | FAILED / 20 / REVIEW_REQUIRED | 동일 | 동일 | 미디어 파일 크기 제한도 FAILED 원인에 포함 |

100000 step 예산이 소진됐다. v42는 진입점 발견에 83148 step, 흐름에 16073 step을 사용했다.
1000개 인벤토리 메타데이터 계약도 넘어서, 가까운 tsconfig 부재를 증명할 수 없어 별칭을 UNKNOWN으로 보존한다.
진입점 등록 17개를 모두 보안 흐름 검증 완료로 계산하면 안 된다.

### Cloudflare Auth Kit

Cloudflare Workers + Better Auth `^1.6.23` + Drizzle `^0.45.2`. Hono 앱으로 분류하지 않았다.
54개 파일 중 텍스트 38개 보관. 프로젝트 TypeScript 선언은 `^7.0.2`, 분석 파서는 세 버전 모두 `6.0.3`이다.

| 항목 | v40 | v41 | v42 | 평가 |
|---|---:|---:|---:|---|
| TS 후보 / 제출·파싱 / 미제출 | 18 / 18 / 0 | 18 / 18 / 0 | 18 / 18 / 0 | 파싱과 SDK 의미 지원은 별개 |
| 정적 모듈 참조 / 연결 모듈 | 58 / N/A | 58 / N/A | 58 / N/A | 참조 전체의 실행 연결은 미검증 |
| 등록 진입점 / 도달 함수 | 1 / 13 | 1 / 13 | 1 / 13 | 주 fetch 확인 |
| 인수·반환 총계 / wrapper | N/A / 0 | N/A / 0 | N/A / 0 | Next 전용 wrapper 계약과 다름 |
| 상수 SQL 실행 / 미확인 응답 관찰 | 1 / 4 | 1 / 4 | 1 / 4 | 안전한 상수 SQL 근거와 응답 불확실성 분리 |
| 구조 Finding / Rule 경고 | 0 / 0 | 0 / 0 | 0 / 0 | 무경고는 TN이 아님 |
| 시간, ms (2회) | 516, 496 | 506, 503 | 503, 501 | 성능 향상 근거로 일반화하지 않음 |
| 부모 JVM heap 샘플, MiB | 95.7, 132.7 | 181.7, 159.9 | 142.0, 177.3 | Worker 피크 RSS는 NOT_VERIFIED |
| Coverage / Score / Risk | FAILED / 100 / REVIEW_REQUIRED | 동일 | 동일 | 대용량 동영상 2개 제한. 100점은 안전 보증 아님 |

### OpenStarterKit

Next `16.4.3`, React `19.3.1`, Better Auth `^1.7.12`, Prisma `^7.10.1`. 360개 파일 중 텍스트 355개 보관.

| 항목 | v40 | v41 | v42 | 평가 |
|---|---:|---:|---:|---|
| TS 후보 / 제출·파싱 / 미제출 | 286 / 100 / 186 | 286 / 100 / 186 | 286 / 100 / 186 | src/lib helper가 파싱 입력에 없음 |
| 정적 모듈 참조 / 연결 모듈 | 460 / N/A | 460 / N/A | 460 / N/A | 모듈 graph 분모는 미검증 |
| 등록 진입점 / 도달 함수 | 36 / 51 | 36 / 51 | 36 / 51 | HTTP 10 + Server Function 26 |
| 인수·반환 총계 / wrapper | N/A / 0 | N/A / 0 | N/A / 0 | 외부 destructured factory는 미지원 |
| 부분 파일 경로 관찰 / 미확인 노출 관찰 | 1 / 4 | 1 / 4 | 1 / 4 | 취약점 확정 아님 |
| 구조 Finding / Rule 경고 | 0 / 14 | 0 / 14 | 0 / 14 | 테스트 서명값 관련 기존 경고 3개 검토 필요 |
| 시간, ms (2회) | 690, 683 | 685, 686 | 704, 685 | 소표본·GC 차이 때문에 속도 개선 주장 없음 |
| 부모 JVM heap 샘플, MiB | 93.1, 90.0 | 130.1, 122.6 | 145.4, 176.1 | Worker RSS 아님 |
| Coverage / Score / Risk | PARTIAL / 0 / BLOCKED | 동일 | 동일 | 구조 검토 후보와 기존 Risk 정책 구분 |

## 실제 Code Flow 검토

아래는 결과를 본 뒤 수행한 비블라인드 코드 검토다. 각 파일 SHA256·고정 URL은 JSON의 `codeFlowReviews`에 있다.

1. **Papermark 정상 입력 구분**: `app/api/help/route.ts:3→5→8`. GET의 q는 필터링에 사용되고 fetch URL은 공개 마케팅 환경 설정에서 온다. 세 버전 모두 HTTP 목적지는 UNKNOWN이지만 요청값이 해당 주소로 들어갔다고 경고하지 않는다. 전체 응답·callback 안전성이나 프로젝트 TN을 주장하지 않는다.
2. **Cloudflare 기존 연결 유지**: `src/index.ts:142→147→26`. fetch→ensureSchema의 객체 인자 안 env.DB→상수 prepare→all이 이미 v40에서 연결된다. 세 버전 모두 STATIC_QUERY 및 실행 관찰, 입력 trace 0. 신규 탐지가 아니다.
3. **Cloudflare 개선되지 않은 SDK 경로**: `src/index.ts:10,347,352`→`src/studio-api.ts:118–119`. 초기화 factory의 반환 함수를 SDK apiHandler callback으로 전달한다. studio-api는 파싱되지만 도달 함수 0. 로컬 정적 import 성공이 SDK dispatch·인증 실행을 증명하지 않는다. Next 전용 v42 계약으로 해결되지 않는다.
4. **Next helper 선택·별칭 경계**: `src/app/api/checkout/route.ts:2,9,19`→`src/lib/auth/index.ts:35`. 401 조기 반환이 실제 소스에 있다. 분석 근거 부재를 인증 부재로 해석하지 않는다. 별칭 후보에 디렉터리와 index.ts가 함께 들어가 모호함으로 처리되며, TypeScript 6.0.3 가상 파일 해석은 index.ts를 선택한다. 하지만 그 파일도 100개 입력에서 빠져 있어 resolver만 고쳐도 종단 간 성공은 보장되지 않는다. Auth·Prisma·Stripe 의미는 추가 미확인이다.
5. **Next 외부 factory 등록 공백**: `src/app/api/auth/[...all]/route.ts:1,7`. 외부 toNextJsHandler 반환 객체에서 GET/POST를 구조 분해한다. 세 버전 모두 파싱되지만 진입점 0. 소스 미확인 factory를 임의 호출하지 않은 결과이며 인증 취약점 FN으로 채점하지 않는다.
6. **Next 경로 보호와 UNKNOWN**: `src/app/blog/covers/[file]/route.ts:49,53,60`. route params→이름 정규식 거부→path.join→readFile. 세 버전 모두 Source→파일 API 부분 경로는 관찰하지만 UNRESOLVED_RESOURCE로 남는다. 정규식 보호를 무시해 Path Traversal로 확정하지 않으며, 런타임 파일시스템 안전성도 보증하지 않는다.

추가 수동 검토: `src/app/api/webhooks/stripe/route.test.ts:93,123,148`의 HARDCODED_FRONTEND_SECRET 3건은
Mock DB/email·Vitest·의도적으로 잘못된 테스트 서명값 문맥이다. 운영 credential/클라이언트 노출로 해석하면 오해가 생긴다.
새 v42 경고가 아니며, 실제 키 검증·번들 검사는 하지 않았다. 전역 FP 통계에 합산하지 않았다.

## 개발·회귀 자료와 분리

| 집합 | v40 | v41 | v42 | 한계 |
|---|---:|---:|---:|---|
| #34-A 고정 Grade B 위험 목표 연결 / 8 | 0 | 8 | 8 | 정상 6·UNKNOWN 5 별도 유지 |
| #34-B 고정 Grade B 위험 목표 연결 / 10 | 1 | 1 | 10 | 정상 8 경고 0·UNKNOWN 8 HIGH 0. 무경고를 TN으로 치환하지 않음 |
| 기존 실앱 15입력 파싱 / 등록 / 도달 함수 | 791 / 143 / 226 | 791 / 143 / 241 | 791 / 143 / 241 | #34-A/B의 SHA 고정 반복 결과 재사용. 새 Holdout 아님 |
| 기존 실앱 구조 후보 | 16 | 16 | 16 | 기존 Rule·Score·Risk·SCA·다른 분석기 결과 보존 |
| 신규 실앱 3개 HIGH 구조 후보 | 0 | 0 | 0 | Grade C. 위 수치와 통합 정확도 계산 금지 |

## 다음 우선순위

1. **타입을 보존하는 경로 인벤토리와 별칭 helper 선택**: 디렉터리/index 후보 혼동과 helper 미제출을 별도로 재현한다. 하나를 해결했다고 나머지까지 해결됐다고 주장하지 않는다. 기존 한도 유지, 실제 모호함·미확인 입력은 UNKNOWN 유지가 종료 조건이다.
2. **인벤토리 완전성·단계별 작업 예산**: 큰 앱에서 1000개 메타데이터 계약과 등록 단계가 흐름 검사 기회를 제한한다. 제한 증액 대신 증거 완전성·근접 설정·helper·진입점별 실행 기회를 검증할 설계가 필요하다. 별도 승인 전 구현하지 않는다.
3. **테스트 서명값의 문맥과 사용자 경고**: 파일명만으로 억제하지 말고 실제 테스트 값·mock·서버/클라이언트 경계를 구분한다. 향후 Risk 결과 영향은 별도 승인과 대조 검증이 필요하다.

Pages Router, 외부 Auth factory 객체, Cloudflare SDK callback, Prisma/Drizzle/Stripe 의미, 일반 class/event/Promise는 미지원 목록으로 보존한다.
이 3개 표본에서 Next는 별칭·helper 선택·외부 factory, Worker는 SDK callback에서 끊겼다. 모집단의 프레임워크별 실패 빈도 순위는 아니다.
새 자료를 이용한 v42 튜닝은 하지 않았다. 다음 구현에서는 이 자료를 Regression으로 전환하고 별도 미사용 검증 자료를 확보해야 한다.

## 재현·보호

`scripts/evaluation/comparison34.py`는 세 고정 checkout·공통 코드 해시·같은 입력·2회 반복을 검증한다.
`module_inventory34.mjs`는 같은 파싱 파일의 구문 참조만 집계하고 가상 메타데이터로 경로를 대조한다.
`comparison34-controls.mjs`는 SecureDeploy 소유의 고정 Grade B만 재평가한다. 코드 실행을 통한 취약점 재현은 없다.
전체 edge·인수·반환 계수를 측정하려고 Worker를 계측·변경하지 않았다. 해당 항목은 NOT_VERIFIED다.
기존 수집기의 크기 검사 순서 때문에 대형 비소스 미디어도 Coverage FAILED 원인에 포함된다. 이를 Worker 전체 실패와 혼동하지 말아야 하며 이번 결과를 유리하게 고치지 않았다.
localhost:8080/5173, Worker v40, 사용자 PostgreSQL·Review·Workspace·Snapshot·비공개 문서 3개는 보존한다.
