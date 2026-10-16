# SecureDeploy 실제 프로젝트 평가 템플릿

- 양식 버전: 1 / 기준일: 2026-10-16 (Asia/Seoul)
- 지원 범위 기준: [현재 분석 지원 범위](current-analysis-support.md)
- 기준 SecureDeploy commit: `a94170a57e4a075189d6ce8686f7b08d5b3be3da`

이 양식은 GitHub 프로젝트 5개의 **검사한 것, 확인된 위험, 검사하지 못한 것, 다음 행동**을 비교하기 위한 것이다. Rule 탐지, 알려진 dependency 문제, 분석 공백, AI 보조 후보를 합산해 탐지 성능으로 표현하지 않는다. 미기입은 0 또는 안전이 아니라 `미확인`이다.

각 평가는 `docs/evaluation/results/NN-repository-YYYY-MM-DD.md`처럼 별도 파일에 복사해 작성한다. 이는 향후 파일명 제안이며 이번 준비 작업에서 결과 5개를 생성하거나 분석한 것은 아니다. 재평가는 기존 기록을 덮어쓰지 않고 새 문서에서 이전 평가를 연결한다. 보고용 API 자료는 credential/개인정보/불필요한 전체 소스/원문 로그를 제거한 뒤 보관한다.

## 1. 평가 식별과 실행 허용 범위

| 필드 | 기록 |
| --- | --- |
| 평가 ID / 작성자 / 검토자 | 미확인 |
| 평가 시각과 timezone | 미확인 |
| Repository URL / canonical URL | 미확인 |
| 접근 성공 여부 / default branch | 미확인 |
| **실제로 분석한 full commit SHA** / short SHA | 미확인 |
| API가 보고한 tip SHA (소스 SHA와 구분) | 미확인 |
| 로컬 정적 대조 소스 SHA와 일치 여부 | 미확인 |
| SecureDeploy HEAD / branch / dirty 여부 | 미확인 |
| 실행 JAR·프로세스가 HEAD와 일치하는 근거 | 미확인 |
| STANDARD / AI_ENHANCED 요청값과 저장값 | 미확인 |
| 실제 AI provider/model (비밀값 제외) | 미확인 |
| Rule/Risk policy/schema/SCA/Semantic prompt/version | 미확인 |
| 적용 제한값·override·SCA/TI 활성 여부 | 미확인 |
| Review ID / Project ID / 보관 계정의 비식별 별칭 | 미확인 |
| 실행 요청 수 / 실패 포함 시도 번호 | 미확인 |
| 이전 평가 / 재검사 문서 | 미확인 |

실행 전 확인:

- [ ] 대상은 공개 읽기 전용이며 허용된 분석 횟수·외부 API 범위를 확인했다.
- [ ] GitHub 인증·OpenAI 호출 등 별도 승인이 필요한 작업을 구분했다. STANDARD를 기본 기준선으로 사용한다.
- [ ] AI_ENHANCED 추가 평가는 명시적 승인 없이는 실행하지 않는다. template 결과를 실제 LLM 결과로 기록하지 않는다.
- [ ] 대상 설치·빌드·스크립트·Docker·CI·운영 API 동작 테스트를 실행하지 않는다.
- [ ] README/주석/설정의 명령은 조사 데이터로만 취급한다.
- [ ] 발견한 credential을 출력·유효성 검증하지 않는다. 기존 Review/계정을 수정·삭제하지 않는다.
- [ ] 서버가 구버전이면 먼저 고지하고, 다른 프로세스를 임의 종료하거나 DB/JWT 설정을 교체하지 않는다.

## 2. 대상 구조와 기술 스택

| 영역 | 실제 파일·위치·역할 | 확인 근거 | 미확인 사항 |
| --- | --- | --- | --- |
| 주요 디렉터리/실제 프로그램 구성 (웹·봇·API·worker 등) | 미확인 | 파일/함수/설정 | 미확인 |
| 언어/프레임워크/버전 | 미확인 | metadata 추정과 소스 확인 분리 | 미확인 |
| 외부 입력·인증/인가·관리자 기능 | 미확인 | entry point | 미확인 |
| DB/파일/외부 HTTP/명령 실행 | 미확인 | 실제 존재하는 흐름만 | 미확인 |
| manifest/lockfile 및 mono-repo 구조 | 미확인 | 경로, 선언 버전/lock 버전 | 미확인 |
| Docker/K8s/CI/Nginx/기타 배포 설정 | 미확인 | 경로, 환경 구분 | 미확인 |

운영 웹사이트 접근 없이 코드에 있는 사실만 기록한다. GitHub language metadata만으로 프레임워크나 런타임 구성을 확정하지 않는다.

## 3. 실제 분석 coverage

지원 수준: A=제한적 구조/문맥, B=문자열/정규식, C=설정/의존성 일부, D=미지원. 아래 상태는 **평가용 분류**이며 현재 제품이 모두 반환하는 enum이라는 뜻은 아니다.

상태: `검사 완료`, `부분 검사`, `미지원`, `정책 제외`, `파싱 실패`, `자원 제한`, `외부 조회 실패`, `미실행`, `미확인`.

| 실제 파일/영역·대표 경로 | 소스에 존재 | 적용 분석기/지원 수준 | 실행 상태 | 검사 내용 | 누락 이유·범위 | API/UI 노출 여부 |
| --- | --- | --- | --- | --- | --- | --- |
| 애플리케이션 핵심 소스 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 인증/인가 흐름 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 설정/secret 관련 파일 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 각 manifest/lockfile | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 배포/CI 설정 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 미지원 언어·의존성 형식 | 미확인 | D 또는 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 제외 디렉터리/생성물/LFS/submodule/symlink | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |

전체 파일 수/지원 대상 파일 수/API scannedFileCount/실제 AST·AI 검토 영역 수를 분리한다. API에 없는 제외 수나 파싱 누락을 임의 계산하지 않는다. 별도 소스 inventory로 추정한 값에는 `정적 대조 추정`이라고 쓴다. Python/requirements/pyproject/Pipfile/poetry 및 다른 생태계 파일이 있다면 반드시 개별 행을 추가한다.

## 4. 기준 분석 실행과 완료 상태

| 지표 | 값 | 출처·해석 |
| --- | --- | --- |
| 시작/끝/경과시간 | 미확인 | timezone, 측정 방법 |
| HTTP status / 오류 메시지(마스킹) | 미확인 | 승인·인증·GitHub/network·resource·parser·제품 예외 구분 |
| 도달한 마지막 단계 | 미확인 | 수집/scan/rule/FP/SCA/save/AI/detail/UI |
| source metadata와 분석 SHA | 미확인 | 성공 저장값과 metadata tip 구분 |
| 분석 파일 수 | 미확인 | SecurityReviewResponse.scannedFileCount |
| 원시 Rule 매치 수 | 미확인 | API는 일반적으로 제공하지 않음. 없으면 미확인 유지 |
| FP 후 Rule 탐지 수 / severity 분포 | 미확인 | vulnerabilities/vulnerabilityCount |
| FP 제외·downgrade·중복 제거 수 | 미확인 | 확보 가능한 관측만; metadata로 원시 수를 역산하지 않음 |
| 참고 Security Score / 기존 deploymentStatus | 미확인 | Rule 참고값, 배포 최종 판단 아님 |
| Risk Assessment / policy / schema / coverage | 미확인 | 저장 snapshot |
| BLOCKING / REVIEW_REQUIRED / SHOULD_FIX / INFORMATIONAL | 미확인 | 반드시 처리/직접 확인/수정 권장/참고 |
| code/dependency/analysis공백별 우선순위 수 | 미확인 | 동일 dependency correlation·alias 중복 여부 확인 |
| source/SCA/risk/remediation/semantic/comparison snapshot | 미확인 | null/저장/실패를 분리 |
| 상세 API/History/브라우저에서 같은 결과 확인 | 미확인 | 코드상 경로 조사와 실제 화면 확인 구분 |

실패한 첫 실행을 숨기거나 정상 결과가 나올 때까지 반복하지 않는다. 재시도가 승인되면 모든 시도와 변경 조건을 기록한다. 수집/분석 실패로 Review가 없으면 `Review 미생성`으로 종료 기록하고 0 findings를 만들지 않는다.

## 5. SCA OSV 및 악용 정보

| 지표 | 값/상태 | 근거·제한 |
| --- | --- | --- |
| 발견 manifest / 파싱 완료·실패·미지원 manifest | 미확인 | 실제 경로 및 지원 parser |
| dependenciesDiscovered / dependenciesAnalyzed | 미확인 | distinct package+version. 전체 위치 수와 다름 |
| EXACT / RANGE / UNRESOLVED | 미확인 | 선언/lock 출처, 범위를 exact로 간주하지 않음 |
| unresolvedDependencies / 누락 DSL 표현 | 미확인 | API에 없는 미인식 표현도 정적 대조로 별도 기록 |
| SCA status / warnings | 미확인 | COMPLETE/PARTIAL/UNAVAILABLE/NO_MANIFEST/DISABLED/null |
| vulnerableDependencies / dependencyVulnerabilities | 미확인 | package 수와 advisory 수 구분 |
| OSV package 조회 완료 / 상세 실패·상한·timeout | 미확인 | 상세 미확인을 조회 안전으로 바꾸지 않음 |
| EPSS/KEV status·조회일·cache freshness | 미확인 | 미수록/조회실패/미적용을 악용 위험 0으로 해석하지 않음 |
| 내장 catalog와 OSV correlation | 미확인 | 원본 Rule count와 통합 Priority count 구분 |

대표 dependency마다 다음 표를 작성한다.

| package/ecosystem | 현재 버전과 출처 파일 | direct/transitive/미확인 | advisory/aliases | 해당 advisory의 fixedVersions | 실제 선언·수정 위치 | 남는 불확실성 |
| --- | --- | --- | --- | --- | --- | --- |
| 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |

사용자 입력 기반 supplemental lookup을 수행한 경우 별도 표로 기록하고 `USER_PROVIDED`와 source에서 확인된 정보의 차이를 명시한다. 외부 조회가 허용되지 않았거나 실행하지 않았으면 `미실행`이다. 알려진 버전 문제는 운영 서비스 공격 성공을 뜻하지 않는다. 여러 fix를 하나의 범용 안전 하한으로 합치지 않는다.

## 6. AI 실행 여부와 독립성

| 항목 | 기록 |
| --- | --- |
| 자동 Semantic 요청 여부 / 실제 provider/model | 미확인 |
| semanticReviewStatus / requestCount / slice 수 / omitted 수 | 미확인 |
| 후보 수 / 기존 finding 보조 근거 수 / rejected / deduplicated | 미확인 |
| input/output/total tokens / billable / usage 출처 | 미확인 |
| 위치 validation 여부와 validator 한계 | 미확인 |
| Rule score/count/severity/confidence/Risk와 후보의 독립성 | 미확인 |
| 수동 AI Review/Summary/Audit/Remediation 실행 여부 | 미확인 |

STANDARD의 Semantic 미실행은 정상이며 `후보 0건으로 안전 확인`이라고 기록하지 않는다. AI_ENHANCED라도 provider/template/context/예산에 따라 미실행일 수 있다. 후보가 생성되면 파일·함수·행 및 실제 방어 처리를 대조한다. validation 통과는 보안 해석의 진실성을 증명하지 않는다. 추가 호출 반복으로 원하는 후보를 유도하지 않는다.

## 7. 대표 결과 대조

10건 이하면 가능한 범위에서 전부, 많으면 우선순위/유형/출처가 다른 약 10건을 선택한다. 선택 기준과 검토 못한 수를 기록한다. 분석 공백 안내도 별도 유형으로 분리한다.

판정 코드: **A**=코드에서 위험 근거 확인, **B**=정상 사용을 잘못 경고했을 가능성, **C**=추가 context/운영 조건이 필요해 보류, **D**=취약점 경고가 아닌 분석 미완료 안내. 지원 수준 A/B/C/D와 혼용하지 않는다. A도 실제 공격 성공 확인을 뜻하지 않는다.

| 번호 | Finding/Rule/advisory ID | 파일·함수·행 | 제품 설명/Severity/Priority | confidence/FP risk/note | 판정 | 짧은 근거·반대 근거 | 추가 확인 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |

항목별 상세 기록:

- 문제 설명과 실제 코드의 일치 여부:
- 입력의 출처와 실제 사용 위치:
- 방어 처리(sanitizer/parameter binding/allowlist/auth/ownership 등)와 누락된 context:
- 마스킹된 짧은 발췌 또는 파일·함수·행 근거:
- 현재 판정과 남은 불확실성:
- 확인/수정할 파일, 다음 행동, 수정 후 확인 방법:

긴 문자열만으로 실제 비밀키라 확정하지 않는다. credential의 존재 가능성과 유효성은 분리하며 유효성 확인을 하지 않는다. 실재 근거 없는 AI 출력은 원본과 분리해 검증 실패/보류로 기록한다.

## 8. 결과 밖의 보안 중요 흐름 2~3개

실제로 존재하는 외부 입력, 인증/권한, 파일, HTTP 요청, DB, 명령, 설정 관리 흐름을 선택한다. 기능이 없으면 `해당 없음`과 근거를 쓰고 억지로 만들지 않는다.

| 흐름 | 선택 이유 | 입력 source | 사용 sink/함수 | 방어 처리·반대 근거 | Rule/SCA/Semantic 탐지 여부 | 미탐 후보 또는 보류 이유 | 필요한 추가 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 2 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 3 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |

미지원 언어라 검사되지 않은 것, 지원 영역에서 놓친 후보, 의도된 제외, 환경 미확인을 구분한다. 이 정적 표본으로 프로젝트 전체의 취약점 정답 목록이나 recall/전체 탐지율을 계산하지 않는다. 검토 표본의 판정별 건수는 분모와 보류 항목을 명시한 기술 통계로만 기록한다.

## 9. 사용자 수정 안내와 상태 전달

| 확인 질문 | 좋음/부분/문제/미확인 | 실제 표시·코드 근거 | 개선 이유 |
| --- | --- | --- | --- |
| 비전문가가 어떤 문제인지 이해할 수 있는가? | 미확인 | 미확인 | 미확인 |
| 실제 확인/수정할 파일과 위치가 정확한가? | 미확인 | 미확인 | 미확인 |
| package와 버전이 선언/lock/사용자 입력 중 어디에서 왔는가? | 미확인 | 미확인 | 미확인 |
| fixedVersions가 해당 advisory의 근거로 한정되는가? | 미확인 | 미확인 | 미확인 |
| lockfile 발견 위치와 직접 수정할 manifest가 다른가? | 미확인 | 미확인 | 미확인 |
| 미지원/미조회/실패/미실행과 정상 미발견을 구분하는가? | 미확인 | 미확인 | 미확인 |
| Risk 판단을 참고 점수보다 우선 해석할 수 있는가? | 미확인 | 미확인 | 미확인 |
| confidence가 실제 공격 확정성으로 과장되는가? | 미확인 | 미확인 | 미확인 |
| 다음 행동과 수정 후 재검사 방법이 구체적인가? | 미확인 | 미확인 | 미확인 |
| 실제 브라우저/모바일 확인인가, 코드 조사뿐인가? | 미확인 | 미확인 | 미확인 |

## 10. 실패와 보관 기록

| 항목 | 기록 |
| --- | --- |
| 실패한 단계/원인/원인이 불명확한 이유 | 미확인 |
| 권한·승인 거부와 기능 검증에 미친 영향 | 없음 또는 구체적으로 기록 |
| 안전한 대체 검증과 남은 공백 | 미확인 |
| 실제 외부 호출 종류/횟수/실패/재시도 | 미확인 |
| 실행하지 않은 검증 | 미확인 |
| 저장 Review ID/상세 재조회/History 확인 | 미확인 또는 미생성 |
| source/risk/SCA/comparison/AI snapshot 상태 | 미확인 |
| 결과 문서/API 요약/화면 근거 보관 위치 | 미확인 |
| 임시 소스/인증 자료/로그 정리 여부 | 미확인 |
| 기존 데이터 보존 확인 방법 | 미확인 |
| SecureDeploy 최종 git status / 코드 변경 여부 | 미확인 |

서버 stdout, prompt/response 원문, password hash, token, 개인 이메일은 보고서에 담지 않는다. 실패 Review가 제품에 저장되지 않아도 평가 실패 기록은 남긴다. Review가 생성되면 승인 없이 자동 삭제하지 않는다. 실패·미검증을 성공으로 바꾸어 쓰지 않는다.

## 11. 개선 후보와 제품 판단

| 우선순위 | 개선 후보 | 실제 근거/판정 항목 | 사용자 배포 판단에 미치는 영향 | 다음 확인 또는 변경 범위 | 지금 구현하지 않는 범위 |
| --- | --- | --- | --- | --- | --- |
| 1 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 2 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |
| 3 | 미확인 | 미확인 | 미확인 | 미확인 | 미확인 |

최종 의견은 “현재 근거로 배포 판단에 사용할 수 있는 부분 / 판단할 수 없는 부분 / 먼저 확인하거나 수정할 것”으로 쓴다. 정적 도구의 READY와 평가자가 확인한 운영 배포 안전성을 동일시하지 않는다. 한 repository만 맞추는 rule 수정 대신 다른 평가에도 적용될 원인과 근거를 제시한다.

## 12. 개선 전후 비교

| 비교 조건/지표 | 이전 평가 | 이후 평가 | 차이의 원인/비교 가능성 |
| --- | --- | --- | --- |
| 대상 SHA/지원 파일·범위 | 미확인 | 미확인 | 같은 입력인지 |
| SecureDeploy SHA/dirty/runtime/schema/policy | 미확인 | 미확인 | 엔진·정책·단순 UI 변화 분리 |
| mode/provider/model/prompt/제한값 | 미확인 | 미확인 | AI·예산 차이 분리 |
| OSV/advisory/EPSS/KEV 조회 시점·cache | 미확인 | 미확인 | 외부 DB 갱신 효과 분리 |
| 완료/미지원/제외/실패 coverage | 미확인 | 미확인 | 줄어든 탐지가 분석 실패 때문인지 |
| 대표 항목별 판정과 confidence/FP | 미확인 | 미확인 | 수정·새 탐지·누락·판단 보류 |
| 우선순위/배포 평가/다음 행동 | 미확인 | 미확인 | reference score와 분리 |

전체 탐지 수가 줄었다고 정확도 향상으로, 늘었다고 성능 향상으로 간주하지 않는다. source 변경, coverage 변경, 공급망 DB 변경, AI 출력 변동, 표시상 중복 통합을 따로 설명한다.

## 13. 다섯 프로젝트 평가 목록

아래는 아직 실행하지 않은 예약 행이다. 각 평가 문서가 생긴 뒤 링크와 상태를 채운다.

| 평가 ID | Repository/주요 스택 | 분석 SHA | SecureDeploy SHA/mode | 완료·실패·미지원 상태 | Review ID | 대표 근거/오탐/미탐 후보 요약 | 결과 문서 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 01 | 미정 | 미확인 | 미확인 | 미실행 | 없음 | 미확인 | 없음 |
| 02 | 미정 | 미확인 | 미확인 | 미실행 | 없음 | 미확인 | 없음 |
| 03 | 미정 | 미확인 | 미확인 | 미실행 | 없음 | 미확인 | 없음 |
| 04 | 미정 | 미확인 | 미확인 | 미실행 | 없음 | 미확인 | 없음 |
| 05 | 미정 | 미확인 | 미확인 | 미실행 | 없음 | 미확인 | 없음 |

## 14. ChatGPT 공유용 완료 요약

```text
[실제 프로젝트 평가 NN — 이름]
1) 대상 구조와 실제 분석 commit:
2) SecureDeploy 버전·실행 코드 일치·모드:
3) 지원/부분 지원/미지원/제외/실패 범위:
4) STANDARD 결과와 완료 상태 (0과 미확인 구분):
5) 실제 위험 근거가 확인된 대표 사례:
6) 오탐 가능 사례와 판단 보류:
7) 미탐 후보·반대 근거·추가 검증:
8) 수정 안내 및 UI 상태 전달 평가:
9) 개선 후보 우선순위 3개와 각각의 근거:
10) Review ID·보관 위치·임시 자료 정리:
11) 실제 외부 호출·미실행 검증·승인 거부 영향:
12) git status·제품 코드 변경 여부:
결론: 배포 판단에 사용할 수 있는 근거 / 아직 판단할 수 없는 영역 / 다음 행동
```
