# Rule·분석 계약 Evidence Registry

기준 소스: `08eb483e22d78a59115b9045ecb45201045f8a2a` · 감사일: 2026-10-28 · Worker v40 / RLS v4 / Deployment v2.

이 자료는 비블라인드 소스·근거 감사입니다. 새 취약점 탐지 성과는 **0건**이며, 독립 평가·운영 안전·모든 CWE/프레임워크 지원을 주장하지 않습니다.

## 읽는 법

- CODE/TEST는 구현과 테스트 정의의 존재를 입증합니다. 테스트 파일 참조 자체가 최신 실행 성공 영수증은 아닙니다.
- EVALUATION은 원래 버전·분모·정답·계층을 유지한 공개 기록입니다. #33.7 재실행 결과가 아닙니다.
- Rule별 TP/FP/FN/TN/UNKNOWN이 별도 측정되지 않았으면 JSON은 null입니다. 분야 평가의 수치를 모든 Rule에 복사하지 않습니다.
- 실제 입력 위치·Sink·증거 trace와 위험 위치가 일치해야 목표 탐지입니다. 무관한 경고·무경고·파싱 증가·선언 발견은 TP/TN이 아닙니다.

## 출력 채널

| 출력 | 고유 Rule ID 수 |
| --- | --- |
| RULE_MATCH | 35 |
| STRUCTURAL_FINDING | 23 |
| SUPABASE_FINDING | 1 |
| DEPLOYMENT_FINDING | 13 |

## PERMIT_ALL_USAGE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | authentication / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Java files, line regex |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Literal .permitAll() with optional whitespace. |
| 방어 처리 | No matcher-order or separate authorization proof. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/PermitAllUsageRule.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/PermitAllUsageRule.java#L24) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:41](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L41) · [src/test/java/com/securedeploy/ai/semantic/SemanticReviewTest.java:135](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/ai/semantic/SemanticReviewTest.java#L135) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A07:2025 / API2:2023 / v5.0.0-8.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Public routes may be intentional; missing auth is not inferred." |

## PY_AUTHORIZATION_INVERTED_OWNER_GUARD

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | idor-bola / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-863 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | Request user/principal and identifier input to supported local Django Model lookup; owner must be real ForeignKey/OneToOneField to settings.AUTH_USER_MODEL or Django User. |
| Sink | Same resource save/delete after inverse owner rejection (denial when equal, mutation on other branch). |
| 위험 조건 | Needs identifier input, proven inversion+denial, mutation, non-unresolved flow, and no independent user-query/owner/role/staff constraint. Bridge cross-checks matching access conclusion and WRITE/DELETE. |
| 방어 처리 | User foreign-key filter/get scope, correctly directed owner rejection, staff/role rejection can prevent candidate; login alone is not object authorization. |
| 코드 | [analyzers/python/authorization.py:396](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/authorization.py#L396) |
| 테스트 정의 | [analyzers/python/test_authorization.py:60](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_authorization.py#L60) · [analyzers/python/test_authorization_permissions.py:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_authorization_permissions.py#L18) · [src/test/java/com/securedeploy/analysis/python/PythonAuthorizationFindingTest.java:25](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/PythonAuthorizationFindingTest.java#L25) |
| 평가 집합 | 21-identity, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A01:2025 / API1:2023 / v5.0.0-8.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "Missing checks, AllowAny, resource.pk==user.pk, mere comparison, unknown managers/properties/middleware/permissions never establish IDOR. Authentication declarations are separate observations; optional branch defenses are intersected." |

## LOCAL_STORAGE_TOKEN

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | jwt / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | JS/TS/React files, same line |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | localStorage plus setItem/getItem plus token/jwt/accessToken/refreshToken case-insensitive. |
| 방어 처리 | Shared path/dummy-context assessment only. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/LocalStorageTokenRule.java:29](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/LocalStorageTokenRule.java#L29) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A07:2025 / API2:2023 /  |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Not XSS exploit or actual authentication-token proof; no cross-line alias handling." |

## PY_JWT_FIXED_SIGNING_KEY

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | jwt / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-321 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | Literal nonempty str/bytes passed as jwt.encode key, recognized imported PyJWT-compatible API. |
| Sink | Actual static jwt.encode HMAC signing shape HS256/HS384/HS512 (default HS256). |
| 위험 조건 | HIGH only FIXED_LITERAL+HMAC_SIGN_CALL with nonpartial path. Common secret/test/dummy/changeme/example values classified FIXED_EXAMPLE, not this candidate. Bridge checks matching SIGN/HMAC/FIXED_LITERAL observation. |
| 방어 처리 | Environment key and environment literal fallback are separately observed, not certified entropy/rotation defenses. |
| 코드 | [analyzers/python/token_security.py:58](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/token_security.py#L58) |
| 테스트 정의 | [analyzers/python/test_token_security.py:34](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_token_security.py#L34) · [src/test/java/com/securedeploy/analysis/python/PythonTokenFindingTest.java:34](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/PythonTokenFindingTest.java#L34) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A07:2025 / API2:2023 / v5.0.0-13.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "Asymmetric/unknown options or headers become unresolved; local jwt module/shadowed/rebound symbol not trusted; no key validity or installed PyJWT version verification; no password-hash inference." |

## PY_JWT_UNVERIFIED_ACCESS_DECISION

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | jwt / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-347 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | Request header/query/body/route value to verified jwt.decode, then supported claim extraction. |
| Sink | Claim conditional with supported access rejection on either branch. |
| 위험 조건 | Explicit static options verify_signature=False plus ACCESS_REJECTION_BRANCH and known token/claim path; source must be accepted request kind. Bridge checks token trace/call observation. |
| 방어 처리 | Default/enabled signature options not bypass; legacy verify=False is version-dependent observation, not treated as PyJWT2 signature bypass. |
| 코드 | [analyzers/python/token_security.py:92](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/token_security.py#L92) |
| 테스트 정의 | [analyzers/python/test_token_security.py:22](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_token_security.py#L22) · [src/test/java/com/securedeploy/analysis/python/PythonTokenFindingTest.java:19](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/PythonTokenFindingTest.java#L19) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A07:2025 / API2:2023 / v5.0.0-9.1.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "Display-only decode, generic conditions, unknown validators/transforms/dynamic options, no request source or unsupported denial are not confirmed candidates; external validation unknown." |

## WEAK_JWT_SECRET

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | jwt / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Configuration jwt.secret key |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Non-placeholder value; lowercased value length<32 OR weak list OR repeated character OR all digits OR all letters. All-letter rule also catches long alphabetic literals. |
| 방어 처리 | Placeholder excluded. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/WeakJwtSecretRule.java:36](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/WeakJwtSecretRule.java#L36) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:64](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L64) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A07:2025 / API2:2023 / v5.0.0-13.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No entropy/algorithm/runtime library validation; lowercasing means uppercase/lowercase checks are not independent." |

## SUPABASE_BROAD_WRITE_DECLARATION

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | rls-grants / 부분 지원 |
| 분석기/출력 | TS_RLS / SUPABASE_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Per table, at least one anon/authenticated non-SELECT operation with explicit table or UPDATE-column capability and disabled RLS or supported broad/one-sided UPDATE policy. Unknown table/scope suppresses candidate, not proof of safety. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Per table, at least one anon/authenticated non-SELECT operation with explicit table or UPDATE-column capability and disabled RLS or supported broad/one-sided UPDATE policy. Unknown table/scope suppresses candidate, not proof of safety. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [analyzers/typescript/supabase.mjs:96](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/supabase.mjs#L96) · [analyzers/typescript/supabase.mjs:91](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/supabase.mjs#L91) · [analyzers/typescript/analyzer.mjs:1191](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/analyzer.mjs#L1191) |
| 테스트 정의 | [analyzers/typescript/test/supabase.test.mjs:77](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/supabase.test.mjs#L77) · [analyzers/typescript/test/rls-column-enforcement23.test.mjs:8](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/rls-column-enforcement23.test.mjs#L8) |
| 평가 집합 | 23-rls, 30-replay |
| 실제 앱 연결 | vibe4, apps30, sql-oracles |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A01:2025 / API1:2023, API3:2023 / v5.0.0-8.2.2, v5.0.0-8.2.3 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## HARDCODED_FRONTEND_SECRET

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | secret-literals / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | JS/TS/React/frontend config plus env files |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | ENV secret-like key plus recognized credential or >=32-char sufficiently diverse entropy candidate. JS-like secret/token/api-key quoted assignment >=8 chars (less restrictive than ENV). |
| 방어 처리 | Supabase publishable key excluded; dummy values excluded; ENV URLs/hex/UUID/public pk formats excluded; contextual reconciliation and generic ENV dedup. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/HardcodedFrontendSecretRule.java:81](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/HardcodedFrontendSecretRule.java#L81) |
| 테스트 정의 | [src/test/java/com/securedeploy/rule/filter/FalsePositiveAnalyzerTest.java:270](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/rule/filter/FalsePositiveAnalyzerTest.java#L270) · [src/test/java/com/securedeploy/rule/rules/DisplayContextIntegrationTest.java:44](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/rule/rules/DisplayContextIntegrationTest.java#L44) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "JS branch does not require ENV entropy check; no credential validity/production use proof." |

## HARDCODED_PASSWORD

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | secret-literals / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | YAML/properties/env configuration declarations |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Normalized password/db.password/database.password/datasource.password/spring.datasource.password or any .password suffix; non-placeholder nonblank value not masked by four or more *, x, X. |
| 방어 처리 | External placeholder ${, #{, $env: and masked values excluded; shared false-positive pass applies. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/HardcodedPasswordRule.java:33](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/HardcodedPasswordRule.java#L33) |
| 테스트 정의 | [src/test/java/com/securedeploy/review/SecurityReviewFalsePositiveApiIntegrationTest.java:60](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/review/SecurityReviewFalsePositiveApiIntegrationTest.java#L60) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Flat/indentation heuristic parser, no runtime profiles, escapes or complete YAML resolution." |

## HARDCODED_SECRET

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | secret-literals / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | YAML/properties/env configuration declarations |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Normalized secret,jwt.secret,api.key,apikey,client.secret,oauth.client.secret or .secret/.api.key suffix; non-placeholder. VITE_/NEXT_PUBLIC_ env declarations additionally require credentialCandidate. |
| 방어 처리 | Public-env dummy/identifier values filtered; generic env match wins over frontend duplicate. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/HardcodedSecretRule.java:36](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/HardcodedSecretRule.java#L36) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:28](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L28) · [src/test/java/com/securedeploy/review/SecurityReviewFalsePositiveApiIntegrationTest.java:61](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/review/SecurityReviewFalsePositiveApiIntegrationTest.java#L61) · [src/test/java/com/securedeploy/ai/remediation/FindingRemediationTest.java:40](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/ai/remediation/FindingRemediationTest.java#L40) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Not credential validity, entropy or production-use proof; shared false-positive analysis may lower/exclude." |

## PY_SENSITIVE_DATA_EXPOSURE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | secret-response / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-200 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | Recognized credential-shaped literal; django.conf.settings.SECRET_KEY; known Authorization/Cookie request-header lookups. Arbitrary env values only SENSITIVITY_UNVERIFIED. |
| Sink | Returned Django JsonResponse/HttpResponse or DRF Response; logging levels on known logging function/logger or builtins.print. |
| 위험 조건 | HIGH only SENSITIVE_FLOW_CANDIDATE without partial/unknown exposure flow; constructing unused response is not return. Bridge needs matching exposure use+source. |
| 방어 처리 | Overwrites and fixed branches can remove flow; unknown masking never certifies safety or confirmed leak. |
| 코드 | [analyzers/python/exposure.py:53](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/exposure.py#L53) |
| 테스트 정의 | [analyzers/python/test_exposure.py:16](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_exposure.py#L16) · [src/test/java/com/securedeploy/analysis/python/ExposureFindingTest.java:19](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/ExposureFindingTest.java#L19) |
| 평가 집합 | 22-secret, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API3:2023 / v5.0.0-14.2.4, v5.0.0-16.2.5 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "Credential-shaped values not validity proof; variable names/environment references alone insufficient; unknown encoder/json_dumps options or branch execution keep unresolved; log access/masking/runtime unknown." |

## TS_SENSITIVE_DATA_EXPOSURE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | secret-response / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-200 |
| 지원 범위 | Deno.serve/고정 std serve, 제한된 Next Route Handler/Server Function, Express json/send/end, Cloudflare형 반환 및 console 로그. |
| Source | 서버 비밀 env 분류·요청 선택 env·인증 헤더·credential 형태 literal |
| Sink | 확인된 응답 전송/반환·Server Function 반환·로그 인자 |
| 위험 조건 | null |
| 방어 처리 | 공개 설정·Supabase anon/publishable와 서버 secret 구분; 서버 내부 사용은 응답 노출이 아님. 객체 직렬화·helper 전달의 제한된 추적. |
| 코드 | [analyzers/typescript/analyzer.mjs:163](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/analyzer.mjs#L163) · [analyzers/typescript/exposure.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/exposure.mjs#L1) · [analyzers/typescript/deno.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/deno.mjs#L1) |
| 테스트 정의 | [analyzers/typescript/test/secret-flow.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/secret-flow.test.mjs#L1) · [analyzers/typescript/test/deno-exposure.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/deno-exposure.test.mjs#L1) · [analyzers/typescript/test/next.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/next.test.mjs#L1) |
| 평가 집합 | 22-secret, 30-replay |
| 실제 앱 연결 | vibe4, apps30 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API3:2023 / v5.0.0-14.2.4, v5.0.0-16.2.5 |
| AI 패치 | LEGACY_BACKEND_COMPATIBILITY_ONLY_FOR_IDENTICAL_BOUNDED_DENO_CONTRACT; NOT_CURRENT_UI_FIX_OPTION |
| 결정적 수정 | ONLY_DIRECT_SUPPORTED_DENO_RESPONSE_JSON_OBJECT_FIELD_REMOVAL_WITH_NORMAL_FIELDS_REMAINING |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["실제 key 유효성·운영 접근성 미확인","Server Function 실제 외부 호출·클라이언트 bundle 미검증","마스킹·custom toJSON·복잡한 helper는 불확실"] |

## JS_EVAL_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | code-evaluation / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-95 |
| 지원 범위 | 정적으로 연결된 Express 요청의 shadowing되지 않은 지원 eval 호출. |
| Source | Express req 입력 |
| Sink | eval 인자 |
| 위험 조건 | null |
| 방어 처리 | 고정값 대조·코드 실행 대신 명시적 데이터 변환 권고. |
| 코드 | [analyzers/typescript/node-server.mjs:171](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/node-server.mjs#L171) |
| 테스트 정의 | [analyzers/typescript/test/express.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/express.test.mjs#L1) · [analyzers/typescript/test/entry-state.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/entry-state.test.mjs#L1) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.3.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["모든 JS 실행 API나 샌드박스 분석 아님","미들웨어·동적 호출·실행 성공 미검증"] |

## JS_SHELL_COMMAND_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | command / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-78 |
| 지원 범위 | 정적 출처 확인 child_process/node:child_process exec/execSync와 제한된 정규식 캡처·helper·별칭. |
| Source | Express req 입력과 지원 캡처 |
| Sink | shell command 문자열 |
| 위험 조건 | null |
| 방어 처리 | 고정 실행 파일·shell 미사용 인자 배열 관찰과 제한된 토큰 형태 구분. |
| 코드 | [analyzers/typescript/node-server.mjs:161](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/node-server.mjs#L161) · [analyzers/typescript/regex-flow.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/regex-flow.mjs#L1) |
| 테스트 정의 | [analyzers/typescript/test/shell-flow.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/shell-flow.test.mjs#L1) · [analyzers/typescript/test/regex-flow.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/regex-flow.test.mjs#L1) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | dvna-shell-sql, goof-shell |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.5 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["execFile은 인자 주입·실행 파일 안전 전체 보장이 아님","임의 shell 옵션·프로세스 API·정규식은 UNKNOWN","운영 명령 실행 금지·미검증"] |

## DJANGO_SECURE_COOKIE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | cookie-session / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | SESSION_COOKIE_SECURE or CSRF_COOKIE_SECURE explicitly False. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | SESSION_COOKIE_SECURE or CSRF_COOKIE_SECURE explicitly False. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:19](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L19) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:121](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L121) |
| 평가 집합 | 27-web, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A07:2025 / API2:2023 / v5.0.0-3.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## INSECURE_COOKIE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | cookie-session / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Configuration secure/http.only/http.cookie.secure/http.cookie.http.only or suffix .secure/.http.only |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Explicit boolean false. |
| 방어 처리 | True/unknown values do not match. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/InsecureCookieRule.java:23](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/InsecureCookieRule.java#L23) |
| 테스트 정의 | [src/test/java/com/securedeploy/editing/WorkspacePatchTest.java:204](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/editing/WorkspacePatchTest.java#L204) |
| 평가 집합 | 27-web, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A07:2025 / API2:2023 / v5.0.0-3.3.1, v5.0.0-3.3.2, v5.0.0-3.3.4 |
| AI 패치 | ONLY_SIMPLE_PROPERTIES_CONSTANTS_WITH_EXACT_SOURCE_AND_PROVIDER_CONSENT |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Broad suffix selector may match non-cookie secure keys; proxy/TLS/runtime unknown." |

## JS_SESSION_COOKIE_ATTRIBUTE_REVIEW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | cookie-session / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-1004 |
| 지원 범위 | express-session1.18.1, middleware 선행·scope·req.session 참조와 응답 연결. |
| Source | 세션 middleware 설정·req.session 참조 |
| Sink | httpOnly:false가 적용된 응답 경로 |
| 위험 조건 | null |
| 방어 처리 | 기본 HttpOnly와 일반 UI cookie 구분; Secure/SameSite/Domain/만료는 별도 선언 근거. |
| 코드 | [analyzers/typescript/web-security.mjs:129](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/web-security.mjs#L129) |
| 테스트 정의 | [analyzers/typescript/test/web27.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/web27.test.mjs#L1) |
| 평가 집합 | 27-web, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A07:2025 / API2:2023 / v5.0.0-3.3.1, v5.0.0-3.3.2, v5.0.0-3.3.4 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["실제 token/session 결합·재발급·서버 폐기·proxy TLS 미확인","SameSite 선언은 CSRF 방어 보장 아님"] |

## CORS_WILDCARD

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | cors / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Java files, one line at a time |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | @CrossOrigin optional origins= and optional opening brace followed by quoted *. |
| 방어 처리 | No allowlist/credentials/middleware model. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/CorsWildcardRule.java:26](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/CorsWildcardRule.java#L26) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:41](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L41) |
| 평가 집합 | 27-web, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-3.4.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Multiline or programmatic CORS and effective registration not modeled; string/comment false signals possible." |

## JS_CORS_CREDENTIAL_REFLECTION

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | cors / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-942 |
| 지원 범위 | cors2.8.5 선언, 제한된 Express 등록 순서·scope·terminal 응답. |
| Source | 확인된 민감 응답 Source |
| Sink | origin:true + credentials:true가 적용된 응답 |
| 위험 조건 | null |
| 방어 처리 | 고정Origin·공개wildcard·wildcard+credentials의 브라우저 차단 구분. |
| 코드 | [analyzers/typescript/web-security.mjs:101](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/web-security.mjs#L101) |
| 테스트 정의 | [analyzers/typescript/test/web27.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/web27.test.mjs#L1) |
| 평가 집합 | 27-web, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-3.4.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["동적 origin callback·raw 헤더·Next cookies/CORS 미지원","설정 정적 연결이지 실제 browser 읽기/인증 성공 아님"] |

## PY_UNSAFE_DESERIALIZATION_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deserialization / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-502 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | Request body bytes, uploaded file stream/read, valid io.BytesIO; helpers preserve input. |
| Sink | pickle.loads/load; yaml.unsafe_load/unsafe_load_all and yaml.load/load_all with verified unsafe Loader/CLoader/UnsafeLoader/CUnsafeLoader. |
| 위험 조건 | Raw candidate requires input trace and not safe parser or invalid argument type. Known immediate flow HIGH; unknown loader/lazy _all/unsupported stream MEDIUM; connected only observed HIGH immediate unsafe use. |
| 방어 처리 | json.load(s), yaml.safe_load(_all), explicit SafeLoader/CSafeLoader/BaseLoader/CBaseLoader are safe-parser declarations for this condition, not general schema/field safety. |
| 코드 | [analyzers/python/worker.py:1051](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/worker.py#L1051) |
| 테스트 정의 | [analyzers/python/test_resources.py:59](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_resources.py#L59) · [src/test/java/com/securedeploy/analysis/python/PythonResourceFindingTest.java:30](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/PythonResourceFindingTest.java#L30) · [analyzers/python/test_resource_variations.py:31](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_resource_variations.py#L31) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A08:2025 / 직접 대응 미지정 / v5.0.0-1.5.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "Pickle text from query/header is unsupported argument type and not emitted; pickle.load needs uploaded-file/binary-stream; YAML file-handle unknown; lazy generators not execution proof; library version/exploitability unknown." |

## PY_ERROR_DETAIL_EXPOSURE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | error-logging / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-209 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | traceback.format_stack() with no args, or traceback.format_exc() in narrowly proven active exception handler. |
| Sink | Returned supported Django/DRF response. |
| 위험 조건 | Internal error provenance selected only HTTP_RESPONSE_RETURN; bridge matching SENSITIVE_FLOW_CANDIDATE; avoids duplicate generic sensitivity finding. |
| 방어 처리 | Unused constructed response and ordinary internal diagnostic logs do not become response findings; overwrite/constant branch can remove flow. |
| 코드 | [analyzers/python/exposure.py:53](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/exposure.py#L53) |
| 테스트 정의 | [analyzers/python/test_service_security.py:11](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_service_security.py#L11) · [src/test/java/com/securedeploy/analysis/python/ServiceSecurityFindingTest.java:25](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/ServiceSecurityFindingTest.java#L25) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / 직접 대응 미지정 / v5.0.0-16.5.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "General try/except unsupported except narrow one-literal-raise/one-known-handler ending in return. format_exc outside supported active handler unresolved; custom traceback module/unknown masking unresolved." |

## PY_HTTP_TIMEOUT_REVIEW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | error-logging / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-400 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | Known unshadowed requests/httpx module call in supported request execution path; no attacker URL required. |
| Sink | Module-level get/post/put/patch/delete/head/options/request API. |
| 위험 조건 | HIGH when requests default lacks timeout OR either library explicit timeout=None; no partial/uncertain call path. Bridge checks matching service-use status. |
| 방어 처리 | HTTPX default inactivity timeout is observed, not flagged; positive numeric timeout and requests positive connect/read pair observed but not total-deadline proof. |
| 코드 | [analyzers/python/service_security.py:45](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/service_security.py#L45) |
| 테스트 정의 | [analyzers/python/test_service_security.py:27](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_service_security.py#L27) · [src/test/java/com/securedeploy/analysis/python/ServiceSecurityFindingTest.java:25](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/ServiceSecurityFindingTest.java#L25) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A10:2025 / 직접 대응 미지정 / v5.0.0-13.2.6 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "Sessions/custom clients/dynamic timeout/unknown library versions and patches unresolved; no actual HTTP call, outage, SSRF or total deadline proof." |

## STACKTRACE_EXPOSURE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | error-logging / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Configuration normalized server.error.include.stacktrace |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Value always (case insensitive). |
| 방어 처리 | never and other values do not match. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/StacktraceExposureRule.java:23](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/StacktraceExposureRule.java#L23) |
| 테스트 정의 | [src/test/java/com/securedeploy/editing/WorkspacePatchTest.java:203](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/editing/WorkspacePatchTest.java#L203) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / 직접 대응 미지정 / v5.0.0-16.5.1 |
| AI 패치 | ONLY_SIMPLE_PROPERTIES_CONSTANTS_WITH_EXACT_SOURCE_AND_PROVIDER_CONSENT |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No runtime exception/rendering verification." |

## TS_ERROR_DETAIL_EXPOSURE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | error-logging / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-209 |
| 지원 범위 | 지원 JS/TS 서버 응답 경로의 내부 error detail provenance. |
| Source | 추적한 내부 Error 상세·stack |
| Sink | 확인된 HTTP 응답 반환 |
| 위험 조건 | null |
| 방어 처리 | 일반 메시지와 추적ID·제한 내부로그를 분리; 내부 진단로그만으로 외부 응답 취약으로 승격하지 않음. |
| 코드 | [analyzers/typescript/analyzer.mjs:163](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/analyzer.mjs#L163) · [analyzers/typescript/exposure.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/exposure.mjs#L1) |
| 테스트 정의 | [analyzers/typescript/test/error-security.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/error-security.test.mjs#L1) · [analyzers/typescript/test/error-variations.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/error-variations.test.mjs#L1) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / 직접 대응 미지정 / v5.0.0-16.5.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["실제 오류 발생·운영 렌더러·로그 ACL 미확인","모든 예외 타입·logger 아님"] |

## JS_MONGO_WHERE_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | nosql / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-943 |
| 지원 범위 | 공식 MongoDB driver 출처·지원 연결/collection 생성·제한된 메서드와 소비 호출을 연결하는 계약. |
| Source | Express 입력 |
| Sink | 확인한 collection의 $where 문자열과 실행 요청 |
| 위험 조건 | null |
| 방어 처리 | find는 cursor 생성만 관찰; 지원 소비가 있어야 실행 후보. 고정 조건 대조. |
| 코드 | [analyzers/typescript/node-server.mjs:185](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/node-server.mjs#L185) · [analyzers/typescript/constructor-summary.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/constructor-summary.mjs#L1) |
| 테스트 정의 | [analyzers/typescript/test/receiver-provenance.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/receiver-provenance.test.mjs#L1) · [analyzers/typescript/test/constructor-summary.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/constructor-summary.test.mjs#L1) |
| 평가 집합 | 18-states, 19-states, 20-field, 24-injection, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.4 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["DB 서버의 JS 설정·설치 버전 미확인","일반 query 객체 존재만으로 NoSQL 취약점이 아님","동적 초기화·unknown 객체는 승격하지 않음"] |

## JS_MONGOOSE_SELECTOR_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | nosql / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-943 |
| 지원 범위 | 선언 major4~8, 제한된 model/flat schema, find/findOne 및 await/exec. callback 실행 계약은4~6, 7/8 callback은 미지원. |
| Source | 객체가 될 수 있는 요청 필드 |
| Sink | 검증된 model 검색 filter와 실행 요청 |
| 위험 조건 | null |
| 방어 처리 | 필드별 String/typeof 조기 종료와 제한된 validator.isEmail; sanitizeFilter(v6+) 선언·trusted 예외·filter 변경 구분. |
| 코드 | [analyzers/typescript/mongoose.mjs:6](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/mongoose.mjs#L6) · [analyzers/typescript/field-validation.mjs:87](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/field-validation.mjs#L87) |
| 테스트 정의 | [analyzers/typescript/test/mongoose.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/mongoose.test.mjs#L1) · [analyzers/typescript/test/mongoose-callback.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/mongoose-callback.test.mjs#L1) · [analyzers/typescript/test/field-validation.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/field-validation.test.mjs#L1) |
| 평가 집합 | 18-states, 19-states, 20-field, 24-injection, 30-replay |
| 실제 앱 연결 | goof-nosql20, flint18-19 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.4 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["한 필드 검사는 다른 필드를 보호하지 않음","isEmail은 모든 인자의 primitive string을 자동 보장하지 않음","schema cast·hooks·callback 본문·운영 DB 효과 미검증","FlintCMS 전체 시작 class/DB event는 여전히 별도 미지원"] |

## JS_FILE_PATH_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | path / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-22 |
| 지원 범위 | 출처 확인 fs/fs.promises/path의 지원 read/write/stream/unlink/rename API overload. |
| Source | 지원 요청의 경로 입력 |
| Sink | 파일 경로 인자(내용 인자와 분리) |
| 위험 조건 | null |
| 방어 처리 | 고정 경로·파일 내용 입력만 변경하는 정상 대조; join/normalize/basename·문자열 prefix를 자동 containment로 보지 않음. |
| 코드 | [analyzers/typescript/file-access.mjs:81](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/file-access.mjs#L81) |
| 테스트 정의 | [analyzers/typescript/test/file26.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/file26.test.mjs#L1) |
| 평가 집합 | 26-file, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A01:2025 / 직접 대응 미지정 / v5.0.0-5.3.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["symlink·권한·OS·실제 기준 디렉터리 미검증","복잡한 파일 업로드 pipeline 미지원","realpath와 callback 이후 보호는 불확실"] |

## PY_FILE_PATH_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | path / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-22 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | Django/DRF request input, route string/path, upload/body data forwarded via supported values/helpers. |
| Sink | builtins.open/io.open; pathlib.Path open/read_text/read_bytes/write_text/write_bytes/unlink. |
| 위험 조건 | Raw candidate may be MEDIUM on unresolved path; connected finding requires HIGH matching observed INPUT_IN_FILE_PATH and no RESOURCE_FLOW_UNRESOLVED. |
| 방어 처리 | django.utils._os.safe_join with known non-root absolute literal base produces lexical confinement only; numeric inputs may remove request taint. Normalization, join and resolve alone are not defenses. |
| 코드 | [analyzers/python/worker.py:1042](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/worker.py#L1042) |
| 테스트 정의 | [analyzers/python/test_resources.py:16](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_resources.py#L16) · [src/test/java/com/securedeploy/analysis/python/PythonResourceFindingTest.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/PythonResourceFindingTest.java#L9) · [analyzers/python/test_resource_variations.py:31](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_resource_variations.py#L31) |
| 평가 집합 | 26-file, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A01:2025 / 직접 대응 미지정 / v5.0.0-5.3.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "Symlinks, permissions, actual read/write scope and runtime not verified. Prefix check/unknown validator/opener do not prove safety. guarded-path mutation/resolve loses or invalidates confinement." |

## UNVALIDATED_REDIRECT

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | redirect / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | JS/TS/React files |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Same line location.href/window.location.href/window.location.assign plus redirectUrl/returnUrl/next case-insensitive. |
| 방어 처리 | Contextual AST suppresses only proven fixed destinations. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/UnvalidatedRedirectRule.java:29](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/UnvalidatedRedirectRule.java#L29) |
| 테스트 정의 | [src/test/java/com/securedeploy/rule/rules/DisplayContextIntegrationTest.java:44](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/rule/rules/DisplayContextIntegrationTest.java#L44) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A01:2025 / 직접 대응 미지정 / v5.0.0-1.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No general URL allowlist proof, router support or unknown-validation certification." |

## DANGEROUS_SQL

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sql / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Java files, individual source lines |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | createNativeQuery with +; prepareStatement with +; createStatement or Statement word; select/insert/update/delete followed by + on the same line. |
| 방어 처리 | JavaSqlAnalyzer may suppress only proven safe method/statement spans and merge legacy matches sharing one traced execution. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/DangerousSqlRule.java:33](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DangerousSqlRule.java#L33) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/javaflow/JavaSqlLegacyBaselineTest.java:31](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/javaflow/JavaSqlLegacyBaselineTest.java#L31) · [src/test/java/com/securedeploy/analysis/javaflow/JavaSqlAnalyzerTest.java:70](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/javaflow/JavaSqlAnalyzerTest.java#L70) · [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:41](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L41) |
| 평가 집합 | 24-injection, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.4 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Split construction/callable queries can be missed by raw rule; string/comments/static statement construction can warn; incomplete AST never establishes safety." |

## JAVA_SQL_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sql / 부분 지원 |
| 분석기/출력 | JAVA_SQL / STRUCTURAL_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | java-sql-v4 supplemental candidate |
| Source | Verified Spring controller+mapping parameters @RequestParam/@PathVariable/@RequestBody; javax/jakarta Servlet HttpServlet doGet/doPost/service/doPut/doDelete with verified request parameter. Servlet scalar getters, cookie.getValue, request arrays/maps/enumerations; bounded local/static helpers and verified injected bean calls. |
| Sink | Typed JDBC Statement/PreparedStatement/CallableStatement execute,executeQuery,executeUpdate,executeLargeUpdate,executeBatch; JdbcTemplate/JdbcOperations query/queryForObject/queryForList/update/batchUpdate/execute; resolved static MyBatis ${@Param} substitution with observed mapper call. |
| 위험 조건 | Only INPUT_IN_QUERY, empty per-use limitations, request/cookie-origin trace, and no related retained DANGEROUS_SQL match become standalone candidates. Finding ID is java-sql: SHA256(version,path,line,column). |
| 방어 처리 | Fixed SQL, value binding, numeric parseInt/parseLong, exact equality/string-literal allowlist narrowing and proven overwrite are recognized within supported execution. String identity cast preserves taint, not a sanitizer. |
| 코드 | [src/main/java/com/securedeploy/analysis/javaflow/JavaSqlAnalyzer.java:108](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/javaflow/JavaSqlAnalyzer.java#L108) · [src/main/java/com/securedeploy/analysis/javaflow/JavaSqlWorker.java:913](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/javaflow/JavaSqlWorker.java#L913) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/javaflow/JavaSqlAnalyzerTest.java:78](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/javaflow/JavaSqlAnalyzerTest.java#L78) · [src/test/java/com/securedeploy/analysis/javaflow/JavaDataAccessTest.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/javaflow/JavaDataAccessTest.java#L24) · [src/test/java/com/securedeploy/analysis/javaflow/JavaServletCollectionTest.java:102](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/javaflow/JavaServletCollectionTest.java#L102) |
| 평가 집합 | 24-injection, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.4 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "No actual type attribution/compiler target execution/database access. Ambiguous types/beans/overloads, qualifiers, profiles, mutable DI, unknown predicates/transforms, dynamic SQL, custom repositories, inherited/ambiguous/dynamic MyBatis, external parents, unsupported loops become unknown. JPA repository contracts and MyBatis-Plus inheritance are observations, not general injection findings. No general Java SSRF/command/XSS/deserialization/auth flow analyzer." |

## JS_SEQUELIZE_SQL_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sql / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-89 |
| 지원 범위 | 선언된 Sequelize major4~6의 제한된 생성자·query·정적 초기화 요약. 대표 통제 버전4.44.4/5.22.5/6.37.5; 선언은 설치 증명이 아님. |
| Source | Express req.body/query/params |
| Sink | 출처 확인 인스턴스의 query SQL 인자 |
| 위험 조건 | null |
| 방어 처리 | 정적 쿼리와 bind/replacements 값 객체 분리; SQL 자체의 사용자 문자열 결합은 바인딩 옵션이 있어도 경고 유지. |
| 코드 | [analyzers/typescript/sequelize.mjs:6](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/sequelize.mjs#L6) · [analyzers/typescript/node-server.mjs:172](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/node-server.mjs#L172) |
| 테스트 정의 | [analyzers/typescript/test/sequelize.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/sequelize.test.mjs#L1) · [analyzers/typescript/test/injection24.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/injection24.test.mjs#L1) |
| 평가 집합 | 24-injection, 30-replay |
| 실제 앱 연결 | dvna-shell-sql, dvna24-control |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.4 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["v7 미지원","전체 ORM·hooks·방언·동적 모델 초기화 미검증"] |

## PY_SQL_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sql / 부분 지원 |
| 분석기/출력 | PY_DJANGO / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-89 |
| 지원 범위 | Django/DRF supported static request flows only; no arbitrary Python program coverage. |
| Source | Bounded Django/DRF entries and shared PYTHON_ENTRIES_AND_VALUES. |
| Sink | Django connection.cursor().execute/executemany; local Django Model.objects.raw emits lazy unresolved candidate. |
| 위험 조건 | Candidate needs query trace; MEDIUM if any query/path/lazy uncertainty, otherwise HIGH. Bridge only promotes matching HIGH INPUT_IN_QUERY with observed execution and no SQL-use limitations. |
| 방어 처리 | execute(sql,params)/executemany value binding, ORM filter/get/exclude values, int conversion and Django int route converter. Params do not repair request data already concatenated into SQL. |
| 코드 | [analyzers/python/worker.py:1145](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/worker.py#L1145) |
| 테스트 정의 | [analyzers/python/test_worker.py:25](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_worker.py#L25) · [analyzers/python/test_string_format.py:11](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/python/test_string_format.py#L11) · [src/test/java/com/securedeploy/analysis/python/PythonAnalysisIntegrationTest.java:66](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/python/PythonAnalysisIntegrationTest.java#L66) |
| 평가 집합 | 24-injection, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.4 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | "No Flask/FastAPI/general Python routes, no arbitrary execute receiver; lazy raw is not execution proof; unknown validators/async/loops/custom manager behavior unresolved." |

## TS_SQL_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sql / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-89 |
| 지원 범위 | JS/TS의 지원 Cloudflare Worker·Pages 요청과 env DB prepare/bind/first/all/run/raw 계약. 실제 D1 binding·배포는 미확인. |
| Source | 요청 본문·query·경로 값 |
| Sink | prepare SQL 구성과 뒤따르는 실행 호출 |
| 위험 조건 | null |
| 방어 처리 | 정적 SQL 값 bind를 분리. 이미 조립한 SQL에 bind를 더해도 안전으로 바꾸지 않음. |
| 코드 | [analyzers/typescript/analyzer.mjs:804](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/analyzer.mjs#L804) · [src/main/java/com/securedeploy/analysis/typescript/ServerFlowFinding.java:91](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/typescript/ServerFlowFinding.java#L91) |
| 테스트 정의 | [analyzers/typescript/test/analyzer.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/analyzer.test.mjs#L1) · [analyzers/typescript/test/quality.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/quality.test.mjs#L1) |
| 평가 집합 | 24-injection, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.4 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["batch 실행 미모델링","동적 receiver·query·불확실 실행은 최종 후보 승격 제외"] |

## TS_SSRF_INPUT_FLOW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | ssrf / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-918 |
| 지원 범위 | 지원 Cloudflare/Deno/Next/Express 요청에서 global fetch 및 출처 확인 Node http/https.get의 제한된 형식. |
| Source | 사용자 제어 URL·host·href |
| Sink | fetch 첫 인자 또는 지원 Node get 목적지 |
| 위험 조건 | null |
| 방어 처리 | 최종 URL 객체의 정확한 protocol/host 제약과 이후 변경 무효화. query/path 조각만 제어하는 경우와 목적지 제어 분리. |
| 코드 | [analyzers/typescript/analyzer.mjs:969](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/analyzer.mjs#L969) · [analyzers/typescript/destination.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/destination.mjs#L1) · [analyzers/typescript/node-server.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/node-server.mjs#L1) |
| 테스트 정의 | [analyzers/typescript/test/ssrf.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/ssrf.test.mjs#L1) · [analyzers/typescript/test/ssrf-quality.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/ssrf-quality.test.mjs#L1) · [analyzers/typescript/test/audit30.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/audit30.test.mjs#L1) |
| 평가 집합 | 25-context, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A01:2025 / API7:2023 / v5.0.0-1.3.6 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["DNS·redirect·내부망 성공 미검증","Axios 등 모든 HTTP 라이브러리 미지원","미지원 overload·wrapper UNKNOWN"] |

## REACT_DANGEROUS_HTML

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | xss / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | JS/TS/React line contains dangerouslySetInnerHTML |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Sink-pattern match; contextual AST can exclude proven passive fixed HTML/translation content. |
| 방어 처리 | InsecureApiUrlContext reconciles proven passive literals; retained warnings explicitly say source link/defense not established. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/ReactDangerousHtmlRule.java:26](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/ReactDangerousHtmlRule.java#L26) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:41](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L41) · [src/test/java/com/securedeploy/evaluation/ApplicationEvaluationRunner.java:82](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/evaluation/ApplicationEvaluationRunner.java#L82) · [src/test/java/com/securedeploy/rule/filter/FalsePositiveAnalyzerTest.java:119](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/rule/filter/FalsePositiveAnalyzerTest.java#L119) |
| 평가 집합 | 25-context, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.1, v5.0.0-1.2.2, v5.0.0-1.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Unknown sanitizer is not proof; active fixed markup retains warning; no general XSS proof." |

## CI_SCRIPT_EXPRESSION

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | ci / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | CWE-78 |
| 지원 범위 | Available event-controlled PR/issue title/body or head_ref expression directly inserted into run text, with known job/step shape. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Available event-controlled PR/issue title/body or head_ref expression directly inserted into run text, with known job/step shape. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L9) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java:35](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java#L35) |
| 평가 집합 | 29-ci, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A05:2025 / 직접 대응 미지정 / v5.0.0-1.2.5 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## CI_UNTRUSTED_PR_EXECUTION

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | ci / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | CWE-829 |
| 지원 범위 | pull_request_target + recognized HEAD checkout + recognized project run/local action + persisted WRITE credentials OR secrets env declaration; known job/step shapes required. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | pull_request_target + recognized HEAD checkout + recognized project run/local action + persisted WRITE credentials OR secrets env declaration; known job/step shapes required. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:8](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L8) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java:34](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java#L34) |
| 평가 집합 | 29-ci, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A03:2025 / 직접 대응 미지정 /  |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## GITHUB_ACTIONS_CURL_PIPE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | ci / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Workflow run lines or lexical fallback |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Same line contains curl or wget,  / , and sh or bash substring. |
| 방어 처리 | No checksum/signature validation recognition. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java:46](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java#L46) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java:14](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java#L14) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 29-ci, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A08:2025 / 직접 대응 미지정 /  |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Substring heuristic, no complete shell/command order parsing or runtime proof." |

## GITHUB_ACTIONS_SECRET_ECHO

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | ci / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Workflow run lines when parseable, otherwise lexical fallback |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Same line contains echo and exact '${{ secrets.' substring after lowercasing. |
| 방어 처리 | Evidence masked; parsed run scope excludes unrelated fields. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java:34](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java#L34) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java:14](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java#L14) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:59](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L59) · [src/test/java/com/securedeploy/analysis/deployment/Supply29BoundaryTest.java:58](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29BoundaryTest.java#L58) · [src/test/java/com/securedeploy/analysis/deployment/Supply29BoundaryTest.java:54](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29BoundaryTest.java#L54) |
| 평가 집합 | 29-ci, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A09:2025 / 직접 대응 미지정 / v5.0.0-16.2.5 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Not actual secret existence, shell execution, masking failure or log exposure proof; whitespace variants may miss." |

## GITHUB_ACTIONS_UNPINNED

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | ci / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | GitHub workflow files; structured uses line scope when parseable |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | uses ref has no @ or ends @main/@master/@develop; local ./ ignored, full 40hex SHA ignored. |
| 방어 처리 | Structured line scope excludes unrelated YAML text when parse succeeds. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java:86](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java#L86) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java:14](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/GitHubActionsSecurityRule.java#L14) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java:38](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java#L38) |
| 평가 집합 | 29-ci, 30-replay |
| 실제 앱 연결 | nextbase29-30 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A03:2025 / 직접 대응 미지정 /  |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Version tags and other branch names not flagged despite broad title; parse failure falls back lexical; action implementation not loaded." |

## DEBUG_ENABLED

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Configuration normalized debug key |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Boolean true (case insensitive). |
| 방어 처리 | False/nonboolean absent declarations do not match. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/DebugEnabledRule.java:23](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DebugEnabledRule.java#L23) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:137](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L137) · [src/test/java/com/securedeploy/ai/remediation/OpenAiRemediationLiveSmokeTest.java:29](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/ai/remediation/OpenAiRemediationLiveSmokeTest.java#L29) · [src/test/java/com/securedeploy/ai/remediation/FindingRemediationTest.java:127](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/ai/remediation/FindingRemediationTest.java#L127) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-15.2.3 |
| AI 패치 | ONLY_SIMPLE_PROPERTIES_CONSTANTS_WITH_EXACT_SOURCE_AND_PROVIDER_CONSENT |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No active environment/profile inference." |

## DJANGO_ALLOWED_HOSTS

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Static string list/tuple contains *. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Static string list/tuple contains *. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L18) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:121](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L121) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## DJANGO_DEBUG

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Supported settings literal DEBUG=True. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Supported settings literal DEBUG=True. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:16](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L16) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:121](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L121) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-15.2.3 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## DJANGO_HTTPS

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | SECURE_HSTS_SECONDS integer zero or SECURE_SSL_REDIRECT explicitly False. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | SECURE_HSTS_SECONDS integer zero or SECURE_SSL_REDIRECT explicitly False. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:20](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L20) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:121](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L121) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A04:2025 / API8:2023 / v5.0.0-12.2.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## DJANGO_SECRET_LITERAL

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Supported nonempty SECRET_KEY string; value redacted; not credential authenticity. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Supported nonempty SECRET_KEY string; value redacted; not credential authenticity. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:17](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L17) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:121](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L121) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## EXPOSED_ACTUATOR

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Configuration management.endpoints.web.exposure.include |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Exact value *. |
| 방어 처리 | Narrower declarations do not match. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/ExposedActuatorRule.java:23](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/ExposedActuatorRule.java#L23) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:41](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L41) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Does not establish endpoint availability/authentication/network exposure." |

## K8S_LATEST_IMAGE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Kubernetes-classified files |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Anchored image:name:latest regex. |
| 방어 처리 | No-tag/digest not specifically latest match. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java:38](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java#L38) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java:13](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java#L13) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Narrow regex; no chart rendering/image inspection/runtime verification." |

## K8S_NODEPORT_EXPOSURE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Kubernetes-classified files |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Line matches type:NodePort case insensitive. |
| 방어 처리 | No firewall/network policy verification. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java:41](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java#L41) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java:13](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java#L13) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Text may be comment; no effective service/object binding or real exposure proof." |

## K8S_PRIVILEGED_CONTAINER

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Kubernetes-classified files, source lines |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Line matches privileged:true case insensitive. |
| 방어 처리 | No external defense proof. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java:35](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java#L35) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java:13](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java#L13) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Not structured YAML; comments/non-container text may match; deployed manifest/overrides unknown." |

## K8S_SECRET_PLAIN_TEXT

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Kubernetes-classified files |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | After any line matching kind:Secret, match anchored password/token/secret/api-key/private-key mapping key. |
| 방어 처리 | Evidence masking only. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java:44](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java#L44) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java:13](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/KubernetesSecurityRule.java#L13) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "inSecret stays true through remainder of file, including later YAML documents; does not distinguish data/stringData encoding or placeholders." |

## NGINX_DIRECTORY_LISTING

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Nginx-classified config, stripped lowercase lines |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | autoindex on; anchored line. |
| 방어 처리 | off not matched. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java:41](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java#L41) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java:12](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java#L12) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 /  |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No include/server/location inheritance, runtime routing or file disclosure proof." |

## NGINX_HTTP_ONLY

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Nginx-classified config, whole file booleans |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | listen80 present, no listen443 or any ssl substring, no return301/308 https:// substring. |
| 방어 처리 | Any matching TLS/redirect substring suppresses. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java:67](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java#L67) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java:12](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java#L12) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A04:2025 / API8:2023 / v5.0.0-12.2.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Not server-block scoped; comments or unrelated blocks can affect suppression; upstream TLS unknown." |

## NGINX_SERVER_TOKENS

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | deployment / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Nginx-classified config lines |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | server_tokens on; anchored line. |
| 방어 처리 | off not matched. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java:53](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java#L53) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java:12](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/NginxSecurityRule.java#L12) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:143](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L143) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 /  |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Version exposure not remotely tested, no include hierarchy." |

## COMPOSE_CAPABILITY

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | cap_add normalized CAP_ prefix; ALL,SYS_ADMIN,SYS_PTRACE,NET_ADMIN,DAC_READ_SEARCH,DAC_OVERRIDE,SYS_MODULE. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | cap_add normalized CAP_ prefix; ALL,SYS_ADMIN,SYS_PTRACE,NET_ADMIN,DAC_READ_SEARCH,DAC_OVERRIDE,SYS_MODULE. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:11](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L11) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:32](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L32) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## COMPOSE_HOST_MOUNT

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Normalized absolute bind source exactly /,/etc,/proc,/sys,/dev,/var/run,/run, not arbitrary descendants. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Normalized absolute bind source exactly /,/etc,/proc,/sys,/dev,/var/run,/run, not arbitrary descendants. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:14](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L14) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:32](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L32) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## COMPOSE_PORT_BINDING

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Supported short/long port declaration with omitted host or 0.0.0.0/::/[::]; even target-only numeric short syntax is broad in this implementation. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Supported short/long port declaration with omitted host or 0.0.0.0/::/[::]; even target-only numeric short syntax is broad in this implementation. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:12](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L12) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:32](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L32) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## COMPOSE_ROOT_OVERRIDE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Static service user root or all-zero UID, with optional group. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Static service user root or all-zero UID, with optional group. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:13](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L13) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:97](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L97) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## COMPOSE_SECURITY_DISABLED

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Exact supported seccomp/apparmor unconfined, label:disable, no-new-privileges:false colon/equal forms. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Exact supported seccomp/apparmor unconfined, label:disable, no-new-privileges:false colon/equal forms. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:15](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L15) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:32](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L32) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## COMPOSE_SOCKET

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | DEPLOYMENT / DEPLOYMENT_FINDING |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Known bind source exactly /var/run/docker.sock or /run/docker.sock, including :ro. |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | 해당 구현의 위험 호출·설정 위치 |
| 위험 조건 | Known bind source exactly /var/run/docker.sock or /run/docker.sock, including :ro. |
| 방어 처리 | 연결된 코드·정상 대조 참조. 방어 부재를 취약성 증명으로 바꾸지 않습니다. |
| 코드 | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:24](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L24) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:10](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L10) · [src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentAnalyzer.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:65](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L65) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["설정·패턴 또는 제한된 정적 경로이며 실제 공격·배포 상태를 확인하지 않습니다."] |

## DOCKER_HOST_NETWORK

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Structured Compose services mapping |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Static network_mode:host. |
| 방어 처리 | Other static modes no match, interpolation UNKNOWN. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java:15](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java#L15) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:36](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L36) · [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:32](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L32) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No actual network namespace/active deployment validation." |

## DOCKER_LATEST_TAG

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Dockerfile or Compose lines |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | FROM or image: followed by image:latest; literal-space regex string forms. |
| 방어 처리 | No-tag image does not match this specific rule. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/DockerLatestTagRule.java:30](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerLatestTagRule.java#L30) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/DockerLatestTagRule.java:12](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerLatestTagRule.java#L12) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No registry/image-content resolution; all stages scanned, flags/registry-port syntax can evade narrow regex." |

## DOCKER_PRIVILEGED

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Structured Compose services mapping |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Static privileged:true, sourced from ComposeInspector observation. |
| 방어 처리 | Comment/non-service fields ignored; false safe declaration; interpolation UNKNOWN. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java:15](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java#L15) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerComposeSecurityRule.java#L9) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java:23](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java#L23) · [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:36](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L36) · [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:32](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L32) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No active services, override/include/env expansion or runtime proof; invalid/alias/duplicate YAML rejected." |

## DOCKER_ROOT_USER

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Dockerfile via DockerRuntimeUser |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Final-stage explicit USER root or zero UID, including local-stage inheritance. |
| 방어 처리 | Build-only root excluded; final non-root suppresses; unknown base/dynamic user remains UNKNOWN. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/DockerRootUserRule.java:21](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerRootUserRule.java#L21) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/DockerRootUserRule.java:10](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerRootUserRule.java#L10) |
| 테스트 정의 | [src/test/java/com/securedeploy/project/progress/ProgressComparisonEngineTest.java:44](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/project/progress/ProgressComparisonEngineTest.java#L44) · [src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java:20](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java#L20) · [src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java:97](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java#L97) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Base-image config/build target/Compose overrides/runtime user not resolved; ONBUILD inheritance unknown." |

## DOCKER_SECRET_ENV

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Dockerfile; bounded DockerEnvironment parser with regex fallback |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Complete parse: nonempty literal or dynamic ENV names containing PASSWORD/TOKEN/SECRET/API_KEY/PRIVATE_KEY; old and key=value syntax. Incomplete parse: legacy ENV name= regex fallback. |
| 방어 처리 | Empty parsed values excluded; names/values omitted or masked; shared false-positive pass. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/DockerSecretEnvRule.java:27](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerSecretEnvRule.java#L27) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/DockerSecretEnvRule.java:12](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/DockerSecretEnvRule.java#L12) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java:21](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java#L21) · [src/test/java/com/securedeploy/analysis/deployment/Supply29BoundaryTest.java:11](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/deployment/Supply29BoundaryTest.java#L11) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.3.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "100k-char/100ms parser, <=199 records; backtick escape/heredocs unsupported -> conservative regex fallback; ARG not a secret finding." |

## OUTDATED_DOCKER_BASE_IMAGE

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | docker-compose / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Dockerfile and Compose; active @Component |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Embedded catalog: node/openjdk/nginx latest; ubuntu 18.04; alpine <=3.12 after parser name/tag normalization. |
| 방어 처리 | Catalog only, no full image SCA. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/OutdatedDockerBaseImageRule.java:25](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/OutdatedDockerBaseImageRule.java#L25) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/OutdatedDockerBaseImageRule.java:11](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/OutdatedDockerBaseImageRule.java#L11) |
| 테스트 정의 | [src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java:55](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java#L55) · [src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java:52](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java#L52) · [src/test/java/com/securedeploy/rule/rules/DependencyRuleBeanRegistrationTest.java:17](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/rule/rules/DependencyRuleBeanRegistrationTest.java#L17) |
| 평가 집합 | 29-docker, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A02:2025 / API8:2023 / v5.0.0-13.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Parser strips digest then defaults missing tag to latest; no registry contents/maintenance verification; static suggested versions are not current universal safety guarantees." |

## JS_RATE_LIMIT_BYPASS_REVIEW

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | rate-abuse / 부분 지원 |
| 분석기/출력 | TS_SERVER / STRUCTURAL_FINDING |
| CWE 명시 분류 | CWE-799 |
| 지원 범위 | express-rate-limit7.5.0의 제한된 registration/options/기본 store 계약. |
| Source | skip 항상 true 또는 초과 handler의 next 선언 |
| Sink | 적용 scope 뒤의 지원 서버 작업 |
| 위험 조건 | null |
| 방어 처리 | 정상 stop·선행/후행 scope·버전별 limit0 의미와 알려진 방어를 분리. |
| 코드 | [analyzers/typescript/rate-limit.mjs:130](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/rate-limit.mjs#L130) |
| 테스트 정의 | [analyzers/typescript/test/rate28.test.mjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/test/rate28.test.mjs#L1) |
| 평가 집합 | 28-rate, 30-replay |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A06:2025 / API4:2023 / v5.0.0-15.2.2 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | NOT_COMPARED |
| 한계 | ["실제 요청차단율·분산 store·proxy IP·WAF·업무별 적정 한도 미확인","설정 부재만으로 신규 Finding 생성 안 함"] |

## PACKAGE_JSON_RISK

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sca / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | package.json source lines |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | curl/wget/rm -rf/sudo/chmod 777 substring -> MEDIUM; else watched event-stream/flatmap-stream/node-ipc/ua-parser-js/colors/faker -> LOW. |
| 방어 처리 | No script-section parser or version confirmation. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/PackageJsonRiskRule.java:30](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/PackageJsonRiskRule.java#L30) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/PackageJsonRiskRule.java:12](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/PackageJsonRiskRule.java#L12) |
| 테스트 정의 | 개별 직접 테스트 식별 부족; 관련 통합 테스트 참조 |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A03:2025 / 직접 대응 미지정 / v5.0.0-15.2.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Keyword scan can match outside scripts; package name alone is not CVE evidence; same ID for both branches." |

## VULNERABLE_GRADLE_DEPENDENCY

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sca / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | GRADLE_BUILD selector using shared GradleManifestParser |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Supported DSL string/named coordinates classified EXACT; same four Java catalog artifact thresholds as Maven. |
| 방어 처리 | Comments/quoted documentation lexed away; unresolved/dynamic versions excluded by legacy adapter. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/VulnerableGradleDependencyRule.java:25](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/VulnerableGradleDependencyRule.java#L25) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/VulnerableGradleDependencyRule.java:11](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/VulnerableGradleDependencyRule.java#L11) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/DependencyRiskDeduplicationTest.java:124](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/DependencyRiskDeduplicationTest.java#L124) · [src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java:54](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java#L54) · [src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java:52](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java#L52) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A03:2025 / 직접 대응 미지정 / v5.0.0-15.2.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "No Gradle evaluation or BOM/version catalog inference; 2m-char parser limit returns no legacy matches on unsupported input; SCA reports separately." |

## VULNERABLE_MAVEN_DEPENDENCY

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sca / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | pom.xml XML-typed files |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Line-oriented dependency block has groupId,artifactId,literal version without ${; catalog matches log4j-core<2.17.1,spring-webmvc<5.3.18,jackson-databind<2.13.4,commons-collections<3.2.2. |
| 방어 처리 | Unresolved placeholders skipped; not external advisory lookup. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/VulnerableMavenDependencyRule.java:25](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/VulnerableMavenDependencyRule.java#L25) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/VulnerableMavenDependencyRule.java:11](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/VulnerableMavenDependencyRule.java#L11) |
| 테스트 정의 | [src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java:41](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/RiskPrioritizationEngineTest.java#L41) · [src/test/java/com/securedeploy/risk/DependencyRiskDeduplicationTest.java:114](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/risk/DependencyRiskDeduplicationTest.java#L114) · [src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java:53](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java#L53) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A03:2025 / 직접 대응 미지정 / v5.0.0-15.2.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Not a Maven resolver/BOM or transitive graph; compact single-line blocks may miss; numeric comparator not full semantic ranges." |

## VULNERABLE_NPM_DEPENDENCY

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | sca / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | package.json or recognized package-lock/yarn/pnpm lock |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | Catalog: event-stream<=3.3.6,lodash<4.17.21,minimist<1.2.6,axios<0.21.1,serialize-javascript<3.1.0. |
| 방어 처리 | No live package installation/audit/network. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/VulnerableNpmDependencyRule.java:32](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/VulnerableNpmDependencyRule.java#L32) · [src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java#L18) · [src/main/java/com/securedeploy/rule/rules/VulnerableNpmDependencyRule.java:13](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/VulnerableNpmDependencyRule.java#L13) |
| 테스트 정의 | [src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java:52](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/dependency/DependencyRulePipelineTest.java#L52) · [src/test/java/com/securedeploy/rule/rules/DependencyRuleBeanRegistrationTest.java:17](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/rule/rules/DependencyRuleBeanRegistrationTest.java#L17) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A03:2025 / 직접 대응 미지정 / v5.0.0-15.2.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Line-oriented manifest parser only dependencies/devDependencies, simplistic ^/~ removal; lock parser watches five packages and limited layouts; comparator strips qualifiers, not semver range solver." |

## INSECURE_API_URL

| 항목 | 근거/판단 |
| --- | --- |
| 분야/상태 | transport / 부분 지원 |
| 분석기/출력 | RULE_ENGINE / RULE_MATCH |
| CWE 명시 분류 | 미지정; 분야 관련성은 제품 CWE 라벨이 아닙니다. |
| 지원 범위 | Frontend source or configuration |
| Source | 패턴/설정 선언 또는 연결된 Source 근거; 모든 Rule에 taint Source가 있는 것은 아닙니다. |
| Sink | DECLARATION_OR_LEXICAL_PATTERN |
| 위험 조건 | http:// address except parsed host localhost,127.0.0.1,[::1]; one warning per line. |
| 방어 처리 | AST context reconciliation can prove documentation/passive data; lookalike localhost domains not exempt. |
| 코드 | [src/main/java/com/securedeploy/rule/rules/InsecureApiUrlRule.java:35](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/rule/rules/InsecureApiUrlRule.java#L35) |
| 테스트 정의 | [src/test/java/com/securedeploy/analysis/typescript/ServerAnalysisIntegrationTest.java:169](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/test/java/com/securedeploy/analysis/typescript/ServerAnalysisIntegrationTest.java#L169) |
| 평가 집합 | 개별 성능 분모 없음 |
| 실제 앱 연결 | Rule별 원본 앱 성과 미확인; 전체 앱 평가를 해당 Rule TP로 사용하지 않음 |
| Rule별 TP/FP/FN/TN/UNKNOWN | 미측정(null); 아래 집합별 기록과 혼합 금지 |
| 기준 관련성 | A04:2025 / 직접 대응 미지정 / v5.0.0-12.2.1 |
| AI 패치 | NOT_SUPPORTED_FOR_THIS_RULE |
| 결정적 수정 | NOT_SUPPORTED_FOR_THIS_RULE |
| 재검사/비교 | ONLY_IF_EXISTING_VERSION_BASELINE_COMPARABILITY_GATES_PASS |
| 한계 | "Disabled/failed parser retains warnings; arbitrary URL presence not runtime traffic proof." |

## 분리된 고정 평가 집합

### 13-source-only

분모: 36 · Original TP12 FP2 FN6 TN8 UNKNOWN8; TN is labelled absence, not protection.

출처: [scripts/evaluation/authorization-intent13-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/authorization-intent13-results.json#L1) · JSON Pointer `/originalSourceOnlyMetrics/counts`

```json
{
  "TP": 12,
  "FP": 2,
  "FN": 6,
  "TN": 8,
  "UNKNOWN": 8
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 13-intent

분모: 36 · Requirement-vs-declaration TP18 FP0 FN0 TN6 UNKNOWN12, not automatic vulnerability classification.

출처: [scripts/evaluation/authorization-intent13-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/authorization-intent13-results.json#L1) · JSON Pointer `/declaredIntentRequirementMetrics/counts`

```json
{
  "TP": 18,
  "FP": 0,
  "FN": 0,
  "TN": 6,
  "UNKNOWN": 12
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 13-contexts

분모: 36 · Plus 24 unique added contexts and 8 duplicate replays =68 processed;36 source packets/60 distinct source+intent contexts. All68 operating authorization UNKNOWN.

출처: [scripts/evaluation/authorization-intent13-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/authorization-intent13-results.json#L1) · JSON Pointer `/regressionStates`

```json
{
  "CONDITIONAL_MATCH": 6,
  "CONFLICT": 18,
  "UNKNOWN": 12
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 18-states

분모: 35 · 8 review-candidate cases,5 static/string,3 sanitize declared,18 unknown,1 construction-only. These are states, not a general TP/TN matrix.

출처: [scripts/evaluation/mongoose18-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/mongoose18-results.json#L1) · JSON Pointer `/controls`

```json
{
  "beforeNotSupportedOrNotApplicable": 35,
  "afterReviewCandidates": 8,
  "afterStaticOrStringFilter": 5,
  "afterSanitizeFilterDeclared": 3,
  "afterUnknown": 18,
  "afterConstructionOnly": 1,
  "unexpectedCandidatesOnNonRiskCases": 0,
  "missedAuthoredRiskCandidates": 0,
  "workerRunsPerCasePerVersion": 2,
  "isolatedH2RunsPerCase": 2,
  "h2ValidatedCandidates": 8,
  "repeatIdentical": true,
  "independentReview": false
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 19-states

분모: 53 · 21 review-candidate cases but22 findings because one case contains2 queries. Preserve six callback-version-unsupported states.

출처: [scripts/evaluation/callback19-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/callback19-results.json#L1) · JSON Pointer `/controls`

```json
{
  "before": {
    "QUERY_CREATED_EXECUTION_NOT_OBSERVED": 35,
    "UNKNOWN": 16,
    "REVIEW_CANDIDATE": 1,
    "SANITIZE_FILTER_DECLARED": 1
  },
  "after": {
    "REVIEW_CANDIDATE": 21,
    "CALLBACK_VERSION_UNSUPPORTED": 6,
    "STATIC_OR_STRING_FILTER": 3,
    "SANITIZE_FILTER_DECLARED": 3,
    "UNKNOWN": 18,
    "QUERY_CREATED_EXECUTION_NOT_OBSERVED": 2
  },
  "rawCandidatesBefore": 2,
  "rawCandidatesAfter": 22,
  "isolatedH2ValidatedCandidates": 22,
  "twoDistinctQueriesInOneCase": true,
  "duplicateQueryFindingPrevented": true,
  "unexpectedCandidatesOnNonRiskCases": 0,
  "missedAuthoredRiskCases": 0,
  "original18Cases": 35,
  "original18ClassificationsUnchanged": true,
  "runsPerEnginePerCase": 2,
  "h2RunsPerCase": 2,
  "repeatIdentical": true,
  "independentReview": false
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 20-field

분모: 36 · 13 risk,4 normal,16 UNKNOWN,1 unreachable,1 created,1 unrelated. After12 risk candidates/1 known miss; no false candidates on4 normal.

출처: [scripts/evaluation/field-validation20-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/field-validation20-results.json#L1) · JSON Pointer `/authoredControls`

```json
{
  "count": 36,
  "truth": {
    "RISK": 13,
    "NORMAL": 4,
    "UNKNOWN": 16,
    "UNREACHABLE": 1,
    "CREATED": 1,
    "UNRELATED": 1
  },
  "before": {
    "riskCandidates": 2,
    "riskUnknownMisses": 11,
    "normalFalseCandidates": 1,
    "normalStaticOrString": 1,
    "normalUnknown": 2,
    "allUnknown": 30
  },
  "after": {
    "riskCandidates": 12,
    "riskUnknownMisses": 1,
    "normalFalseCandidates": 0,
    "normalStaticOrString": 4,
    "normalUnknown": 0,
    "allUnknown": 18
  },
  "knownRiskGap": "nondominating-type: branch merge loses callback version proof; RISK truth unchanged",
  "independent": false
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 21-identity

분모: 26 · Local identity-to-filter evidence completeness and rejection controls, not IDOR TP/FP/FN/TN.10 positive/16 rejection controls;complete positives1 to9;all complete17 to25;false identity proofs0.

출처: [scripts/evaluation/access-control21-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/access-control21-results.json#L1) · JSON Pointer `/authoredContracts`

```json
{
  "grade": "B_AUTHORED_NOT_INDEPENDENT",
  "total": 26,
  "positive": 10,
  "positiveCompleteBefore": 1,
  "positiveCompleteAfter": 9,
  "rejectionControls": 16,
  "falseIdentityProofs": 0,
  "allCompleteBefore": 17,
  "allCompleteAfter": 25,
  "knownPartial": "two-identity-filters: earlier argument escape prevents confirming the second filter",
  "repeatCount": 2
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 22-secret

분모: 90 · After32 static TP,30 reviewed static TN,27 UNKNOWN,1 FN including deferred; not actual-app exploit accuracy.

출처: [scripts/evaluation/secret-exposure22-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/secret-exposure22-results.json#L1) · JSON Pointer `/controls`

```json
{
  "before": {
    "TP_STATIC_CONTRACT": 15,
    "FN_INCLUDING_DEFERRED": 18,
    "TN_REVIEWED_STATIC_CONTROL": 16,
    "NORMAL_DEFERRED_NOT_TN": 10,
    "FP_STATIC_CONTRACT": 4,
    "UNKNOWN": 22,
    "UNEXPECTED_CANDIDATE": 5
  },
  "after": {
    "TP_STATIC_CONTRACT": 32,
    "TN_REVIEWED_STATIC_CONTROL": 30,
    "UNKNOWN": 27,
    "FN_INCLUDING_DEFERRED": 1
  },
  "repeatIdentical": true
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 23-rls

분모: 14 · Before TP4 FP0 FN4 TN6;after TP8 FP0 FN0 TN6. Broad-write declaration review, not deployed vulnerability truth.

출처: [scripts/evaluation/rls-authorization23-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/rls-authorization23-results.json#L1) · JSON Pointer `/staticContracts`

```json
{
  "population": 14,
  "before": {
    "TP": 4,
    "FP": 0,
    "FN": 4,
    "TN": 6
  },
  "after": {
    "TP": 8,
    "FP": 0,
    "FN": 0,
    "TN": 6
  },
  "metricMeaning": "BROAD_WRITE_DECLARATION_REVIEW_NOT_REAL_APP_VULNERABILITY_DETECTION",
  "repeatIdentical": true,
  "baselineGateExit": 2,
  "newGateExit": 0
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 24-injection

분모: {"SQL":51,"NOSQL":16} · Separate SQL and NoSQL populations, not67 independent apps. SQL v35 normal-deferred3 remain distinct from TN12.

출처: [scripts/evaluation/injection-precision24-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/injection-precision24-results.json#L1) · JSON Pointer `/summary`

```json
{
  "SQL": {
    "before": {
      "TP_STATIC_CONTRACT": 3,
      "FN_INCLUDING_DEFERRED": 15,
      "TN_REVIEWED_STATIC_CONTROL": 12,
      "NORMAL_DEFERRED_NOT_TN": 3,
      "FALSE_SAFE_OBSERVATION": 12,
      "UNKNOWN": 3,
      "NOT_INSPECTED": 3
    },
    "after": {
      "TP_STATIC_CONTRACT": 18,
      "TN_REVIEWED_STATIC_CONTROL": 12,
      "NORMAL_DEFERRED_NOT_TN": 3,
      "UNKNOWN": 15,
      "NOT_INSPECTED": 3
    }
  },
  "NOSQL": {
    "before": {
      "TP_STATIC_CONTRACT": 1,
      "FN_INCLUDING_DEFERRED": 4,
      "NORMAL_DEFERRED_NOT_TN": 2,
      "TN_REVIEWED_STATIC_CONTROL": 3,
      "FP_STATIC_CONTRACT": 1,
      "UNKNOWN": 4,
      "NOT_INSPECTED": 1
    },
    "after": {
      "TP_STATIC_CONTRACT": 5,
      "TN_REVIEWED_STATIC_CONTROL": 6,
      "UNKNOWN": 4,
      "NOT_INSPECTED": 1
    }
  }
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 25-context

분모: {"XSS":21,"SSRF":22} · Separate XSS lexical context and SSRF initial-destination tasks. SQL conditional evidence is a separate regression control.

출처: [scripts/evaluation/context-xss-ssrf25-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/context-xss-ssrf25-results.json#L1) · JSON Pointer `/controls`

```json
{
  "before": {
    "xss": {
      "TP": 5,
      "FP": 7,
      "FN": 0,
      "TN": 3,
      "UNKNOWN": 6,
      "NORMAL_DEFERRED": 0,
      "UNEXPECTED_CANDIDATE": 0,
      "FALSE_SAFE_OBSERVATION": 0
    },
    "ssrf": {
      "TP": 0,
      "FP": 0,
      "FN": 12,
      "TN": 1,
      "UNKNOWN": 4,
      "NORMAL_DEFERRED": 5,
      "UNEXPECTED_CANDIDATE": 0,
      "FALSE_SAFE_OBSERVATION": 0
    },
    "sqlConditional": {
      "records": 1,
      "detail": "SEE_SOURCE_RECORD"
    }
  },
  "after": {
    "xss": {
      "TP": 5,
      "FP": 1,
      "FN": 0,
      "TN": 9,
      "UNKNOWN": 6,
      "NORMAL_DEFERRED": 0,
      "UNEXPECTED_CANDIDATE": 0,
      "FALSE_SAFE_OBSERVATION": 0
    },
    "ssrf": {
      "TP": 8,
      "FP": 0,
      "FN": 4,
      "TN": 5,
      "UNKNOWN": 4,
      "NORMAL_DEFERRED": 1,
      "UNEXPECTED_CANDIDATE": 0,
      "FALSE_SAFE_OBSERVATION": 0
    },
    "sqlConditional": {
      "records": 2,
      "detail": "SEE_SOURCE_RECORD"
    }
  }
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 26-file

분모: {"PATH":33,"UPLOAD_TYPE":6} · Path after TP12 FN6 TN8 deferred-normal1 no-fs-sink1 UNKNOWN5; upload FN1 UNKNOWN5.

출처: [scripts/evaluation/file26-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/file26-results.json#L1) · JSON Pointer `/summary`

```json
{
  "before": {
    "PATH": {
      "FN": 18,
      "NORMAL_DEFERRED": 9,
      "NORMAL_NO_FS_SINK": 1,
      "UNKNOWN": 5
    },
    "UPLOAD_TYPE": {
      "FN": 1,
      "UNKNOWN": 5
    }
  },
  "after": {
    "PATH": {
      "TP": 12,
      "FN": 6,
      "TN": 8,
      "NORMAL_DEFERRED": 1,
      "NORMAL_NO_FS_SINK": 1,
      "UNKNOWN": 5
    },
    "UPLOAD_TYPE": {
      "FN": 1,
      "UNKNOWN": 5
    }
  }
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 27-web

분모: {"CORS":16,"COOKIE":12,"CSRF":8} · Do not merge family-specific outcomes. Owned browser canary19 checks is a separate protocol demonstration, not target middleware exploit validation.

출처: [scripts/evaluation/web27-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/web27-results.json#L1) · JSON Pointer `/controls`

```json
{
  "total": 36,
  "risk": 10,
  "normal": 14,
  "unknown": 12,
  "before": {
    "CORS": {
      "FN": 5,
      "NORMAL_DEFERRED": 6,
      "UNKNOWN": 5
    },
    "COOKIE": {
      "FN": 2,
      "NORMAL_DEFERRED": 5,
      "UNKNOWN": 5
    },
    "CSRF": {
      "FN": 3,
      "NORMAL_DEFERRED": 3,
      "UNKNOWN": 2
    }
  },
  "after": {
    "CORS": {
      "FN": 5,
      "TN": 6,
      "UNKNOWN": 5
    },
    "COOKIE": {
      "TP": 2,
      "TN": 2,
      "NORMAL_DEFERRED": 3,
      "UNKNOWN": 5
    },
    "CSRF": {
      "FN": 3,
      "TN": 2,
      "NORMAL_DEFERRED": 1,
      "UNKNOWN": 2
    }
  },
  "falsePositives": 0,
  "repeatIdentical": true,
  "tnMeaning": "Relevant supported declaration or local read-only constraint, not complete security or runtime proof",
  "corsRemainingGap": "The frozen AUTH_TOKEN environment reference is unverified by the pre-existing secret classifier; callback prefix decisions also unsupported. Truth and inputs were not relaxed.",
  "csrfRemainingGap": "Actual automatic cookie authentication and token/session enforcement are not proven; no absence-based vulnerability Finding",
  "normalDeferred": "Preference cookie purpose and regenerate/destroy callback completion; external token verifier",
  "separateApiContractTests": "Five additional authored unit tests exercise supported secret Sources, order, scope, mutation, session declarations and exact Origin exits; not added to benchmark statistics"
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 28-rate

분모: 32 · After TP3 FN7 TN7 deferred-normal3 UNKNOWN12; owned fake-clock/store lab15 checks does not execute real limiter package.

출처: [scripts/evaluation/rate28-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/rate28-results.json#L1) · JSON Pointer `/controls`

```json
{
  "total": 32,
  "risk": 10,
  "normal": 10,
  "unknown": 12,
  "before": {
    "FN": 10,
    "NORMAL_DEFERRED": 10,
    "UNKNOWN": 12
  },
  "after": {
    "TP": 3,
    "FN": 7,
    "TN": 7,
    "NORMAL_DEFERRED": 3,
    "UNKNOWN": 12
  },
  "falsePositives": 0,
  "repeatIdentical": true,
  "tpMeaning": "Authored explicit limiter bypass connected to supported server work; not proven attack, cost, intent violation or production vulnerability",
  "tnMeaning": "Pinned local default stop/zero-block contract, not complete automation prevention",
  "remainingFn": [
    "other-route",
    "too-late",
    "conditional",
    "header-key",
    "upstash-ignored",
    "upstash-inverted",
    "upstash-stale"
  ],
  "normalDeferred": [
    "multiple",
    "public-none",
    "custom-handler"
  ],
  "separateValidation": "Relative module policy and corrected Upstash guard tested separately; no independent source or new accuracy denominator"
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 29-docker

분모: 14 · Static authored Docker controls; actual image/runtime not verified.

출처: [scripts/evaluation/supply29-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/supply29-results.json#L1) · JSON Pointer `/docker`

```json
{
  "total": 14,
  "risk": 6,
  "normal": 4,
  "unknown": 4,
  "before": {
    "TP": 4,
    "FN": 2,
    "FP": 1,
    "TN": 1,
    "NORMAL_DEFERRED": 2,
    "UNKNOWN": 4
  },
  "after": {
    "TP": 5,
    "FN": 1,
    "FP": 0,
    "TN": 4,
    "NORMAL_DEFERRED": 0,
    "UNKNOWN": 4
  },
  "remainingFn": [
    "ARG credential flow"
  ],
  "implemented": [
    "bounded logical ENV declarations and physical key locations",
    "empty credential value exclusion",
    "credential key versus value text",
    "sanitized Dockerfile declaration coverage"
  ],
  "preserved": [
    "default final-stage USER inheritance",
    "unknown registry default user",
    "Compose privileged, host network, capability, socket, host bind and port declarations"
  ],
  "limitations": [
    "No image build, layers, cache, SBOM or registry inspection",
    "No full ARG/RUN secret or COPY/dockerignore flow",
    "Compose target, user overrides, profiles and external merges are not resolved",
    "Read-only socket mount does not prove daemon API isolation",
    "cap_drop, read_only, environment and secrets do not certify whole-container safety"
  ],
  "normalMeaning": "Only the asserted property has a positive declaration proof; not whole-image safety"
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 29-ci

분모: 12 · Static authored CI controls; organization permissions/runtime not verified.

출처: [scripts/evaluation/supply29-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/supply29-results.json#L1) · JSON Pointer `/ci`

```json
{
  "total": 12,
  "risk": 4,
  "normal": 4,
  "unknown": 4,
  "before": {
    "TP": 0,
    "FN": 4,
    "FP": 1,
    "TN": 0,
    "NORMAL_DEFERRED": 3,
    "UNKNOWN": 4
  },
  "after": {
    "TP": 3,
    "FN": 1,
    "FP": 0,
    "TN": 4,
    "NORMAL_DEFERRED": 0,
    "UNKNOWN": 4
  },
  "remainingFn": [
    "environment data later passed to eval"
  ],
  "newRuleIds": [
    "CI_UNTRUSTED_PR_EXECUTION",
    "CI_SCRIPT_EXPRESSION"
  ],
  "implemented": [
    "bounded YAML node parsing without object construction",
    "workflow versus job permission override",
    "declared actions/checkout@v4 PR head and later simple project operation",
    "direct supported event expression in run",
    "real run/uses scope for legacy patterns",
    "local action is not an unpinned remote action"
  ],
  "limitations": [
    "Organization defaults, actual token/secrets, environment approvals and runner isolation unknown",
    "External Action bodies and reusable workflows not loaded",
    "Dynamic conditions, matrix, needs, custom shell and external Action side effects unknown",
    "Legacy secret echo/curl pipe within run remain partial heuristics",
    "No Actions or shell execution"
  ],
  "tpMeaning": "Authored declaration risk candidate, not proven exploitation or repository compromise"
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

### 30-replay

분모: {"XSS":21,"SSRF":22,"SECRET":90,"SQL":51,"NOSQL":16,"PATH":33,"UPLOAD":6,"CORS":16,"COOKIE":12,"CSRF":8,"RATE":32,"DOCKER":14,"CI":12,"RLS":14,"INTENT_PROCESSED":68} · Each named population retains its own version, label semantics and denominator; no grand accuracy total.

출처: [scripts/evaluation/audit30-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/audit30-results.json#L1) · JSON Pointer `/fixedPopulationControls`

```json
{
  "grade": "B_SAME_AUTHOR_NONBLIND",
  "metricsNotPooled": true,
  "xss21": {
    "beforeAfter": {
      "TP": 5,
      "FP": 1,
      "FN": 0,
      "TN": 9,
      "UNKNOWN": 6
    }
  },
  "ssrf22": {
    "before": {
      "TP": 8,
      "FP": 0,
      "FN": 4,
      "TN": 5,
      "UNKNOWN": 4,
      "NORMAL_DEFERRED": 1
    },
    "after": {
      "TP": 9,
      "FP": 0,
      "FN": 3,
      "TN": 6,
      "UNKNOWN": 4,
      "NORMAL_DEFERRED": 0
    },
    "repairedRisk": "ssrf-guard-mutation",
    "completedNormal": "ssrf-allowed",
    "remainingFn": [
      "ssrf-options",
      "ssrf-callback",
      "ssrf-prefix"
    ]
  },
  "secret90": {
    "unchanged": {
      "TP_STATIC_CONTRACT": 32,
      "TN_REVIEWED_STATIC_CONTROL": 30,
      "UNKNOWN": 27,
      "FN_INCLUDING_DEFERRED": 1
    }
  },
  "sql51": {
    "unchanged": {
      "TP_STATIC_CONTRACT": 18,
      "TN_REVIEWED_STATIC_CONTROL": 15,
      "UNKNOWN": 15,
      "NOT_INSPECTED": 3
    }
  },
  "nosql16": {
    "unchanged": {
      "TP_STATIC_CONTRACT": 5,
      "TN_REVIEWED_STATIC_CONTROL": 6,
      "UNKNOWN": 4,
      "NOT_INSPECTED": 1
    }
  },
  "path33": {
    "unchanged": {
      "TP": 12,
      "FN": 6,
      "TN": 8,
      "NORMAL_DEFERRED": 1,
      "NORMAL_NO_FS_SINK": 1,
      "UNKNOWN": 5
    }
  },
  "upload6": {
    "unchanged": {
      "FN": 1,
      "UNKNOWN": 5
    }
  },
  "cors16": {
    "unchanged": {
      "FN": 5,
      "TN": 6,
      "UNKNOWN": 5
    }
  },
  "cookie12": {
    "unchanged": {
      "TP": 2,
      "TN": 2,
      "NORMAL_DEFERRED": 3,
      "UNKNOWN": 5
    }
  },
  "csrf8": {
    "unchanged": {
      "FN": 3,
      "TN": 2,
      "NORMAL_DEFERRED": 1,
      "UNKNOWN": 2
    }
  },
  "rate32": {
    "unchanged": {
      "TP": 3,
      "FN": 7,
      "TN": 7,
      "NORMAL_DEFERRED": 3,
      "UNKNOWN": 12
    }
  },
  "docker14": {
    "unchanged": {
      "TP": 5,
      "FP": 0,
      "FN": 1,
      "TN": 4,
      "UNKNOWN": 4
    }
  },
  "ci12": {
    "unchanged": {
      "TP": 3,
      "FP": 0,
      "FN": 1,
      "TN": 4,
      "UNKNOWN": 4
    }
  },
  "sca": {
    "frozenMockCases": 3,
    "samePackageVersionAliasCount": 1,
    "twoVersionsCount": 2,
    "conflictingFixMetadataCount": 2,
    "sourcePathsPreserved": true,
    "liveFeedAccuracy": "NOT_VERIFIED"
  },
  "rls23": {
    "staticMatches": 14,
    "repeatIdentical": true,
    "postgresExecutedThisAudit": false
  },
  "intent13": {
    "regressionSubset": 36,
    "v40ExpectationMatches": 68,
    "sourceStates": {
      "NO_SOURCE_CANDIDATE_OBSERVED": 50,
      "SOURCE_REVIEW": 18
    },
    "intentStates": {
      "CONDITIONAL_MATCH": 8,
      "CONFLICT": 24,
      "UNKNOWN": 36
    },
    "originalV28ReceiptAlsoReevaluated": true,
    "originalReceiptChanged": false,
    "ownerApprovals": 0,
    "productIntentFindingsPromoted": 0,
    "meaning": "Requirement-versus-declaration interpreter, not automatic vulnerability TP/TN or deployed authorization proof"
  },
  "meaning": "TN is the labelled inspected property, not whole-project safety; known unsupported risk remains FN and unknown is never relabelled as safe"
}
```

같은 작성자·비블라인드. #33.7 재실행 아님. 누락 셀은 0이 아닙니다.

## 실제 앱 근거와 한계

| 공개 기록 식별자 | 확인한 내용 | 근거 |
| --- | --- | --- |
| realworld40 | 20 CVEs in 20 projects, 40 vulnerable/fixed revision cases; final-user outcomes NOT_SUPPORTED38 and RESOURCE_LIMIT2, zero scored coverage. | [scripts/evaluation/realworld-baseline.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/realworld-baseline.json#L1) · [scripts/evaluation/realworld-baseline.json:27](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/realworld-baseline.json#L27) · [scripts/evaluation/realworld-baseline.json:29](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/realworld-baseline.json#L29) |
| pilot38 | 38-case pilot final-user TP12 FP6 TN2 UNKNOWN3 NOT_INSPECTED1 RESOURCE_LIMIT4 NOT_SUPPORTED10. Scored precision 12/18 and all-dangerous detection coverage 12/19 are different from supported-scope recall. | [scripts/evaluation/pilot-baseline.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/pilot-baseline.json#L1) · [scripts/evaluation/pilot-baseline.json:2120](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/pilot-baseline.json#L2120) · [scripts/evaluation/pilot-baseline.json:2138](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/pilot-baseline.json#L2138) |
| dvna-shell-sql | Original 10-path/8-risk target set: shell support gives TP2 TN1; later Sequelize support gives TP4 TN1 NOT_SUPPORTED5. Different revisions can duplicate one defect. The normal ORM counterpart remains unsupported, not TN. | [scripts/evaluation/sequelize-hardening-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/sequelize-hardening-results.json#L1) · [scripts/evaluation/sequelize-hardening-results.json:6](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/sequelize-hardening-results.json#L6) · [scripts/evaluation/sequelize-hardening-results.json:18](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/sequelize-hardening-results.json#L18) |
| goof-shell | Pinned Goof add14ba59e98240d9e00a235dd7d42cd61ae9912 has a documented shell path routes/index.js:168 to :174; public receipt records a structural TP after bounded regex/flow support. | [scripts/evaluation/goof-hardening-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/goof-hardening-results.json#L1) · [scripts/evaluation/goof-hardening-results.json:74](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/goof-hardening-results.json#L74) · [scripts/evaluation/goof-hardening-results.json:99](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/goof-hardening-results.json#L99) |
| goof-nosql20 | #20 records one source-reviewed known Goof NoSQL path TP, zero new independent-project TP, zero runtime-verified TP, and no upstream fixed pair. | [scripts/evaluation/field-validation20-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/field-validation20-results.json#L1) · [scripts/evaluation/field-validation20-results.json:9](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/field-validation20-results.json#L9) · [scripts/evaluation/field-validation20-results.json:11](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/field-validation20-results.json#L11) |
| flint18-19 | FlintCMS vulnerable SHA49e4b6a49e8ba378313845162cd32ba06a2681d6 and patched SHA4ae34238ce39fde00dfa15082397541758c07af1 have zero traced entries and zero target findings in #18. | [scripts/evaluation/mongoose18-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/mongoose18-results.json#L1) · [scripts/evaluation/mongoose18-results.json:32](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/mongoose18-results.json#L32) · [scripts/evaluation/mongoose18-results.json:33](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/mongoose18-results.json#L33) |
| validation5-upstream | #5 retains two real web CVEs and two library CVEs separately: web TP0 FP0 FN0 TN0 NOT_SUPPORTED2; library TP0 FP0 FN0 TN0 NOT_SUPPORTED2 NOT_INSPECTED1 over three risk paths. | [scripts/evaluation/validation5-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/validation5-results.json#L1) · [scripts/evaluation/validation5-results.json:60](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/validation5-results.json#L60) · [scripts/evaluation/validation5-results.json:118](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/validation5-results.json#L118) |
| apps8 | Eight-project application baseline has 19 scoped path reviews; only three conditional dangerous and five narrowly safe paths are labelled, not whole apps. | [scripts/evaluation/application-review.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/application-review.json#L1) · [scripts/evaluation/application-review.json:3](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/application-review.json#L3) · [scripts/evaluation/application-review.json:4](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/application-review.json#L4) |
| vibe4 | Four publicly attributed AI-assisted apps are Grade C, with 16 named manual conditions, no executed controlled repair and no blind holdout. | [scripts/evaluation/vibe-review.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/vibe-review.json#L1) · [scripts/evaluation/vibe-review.json:5](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/vibe-review.json#L5) · [scripts/evaluation/vibe-review.json:7](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/vibe-review.json#L7) |
| dvna24-control | #24 includes an authored retained-source DVNA query-object mutation, separate from the unchanged original and upstream counterpart. | [scripts/evaluation/injection-precision24-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/injection-precision24-results.json#L1) · [scripts/evaluation/injection-precision24-results.json:719](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/injection-precision24-results.json#L719) · [scripts/evaluation/injection-precision24-results.json:721](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/injection-precision24-results.json#L721) |
| apps30 | #30 reports 15 fixed-SHA inputs, 14 unique project IDs, two runs each, preserved findings and source plans; new actual-vulnerability TP0, official vulnerable/fixed pairs0, independent holdout0. | [scripts/evaluation/audit30-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/audit30-results.json#L1) · [scripts/evaluation/audit30-results.json:42](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/audit30-results.json#L42) · [scripts/evaluation/audit30-results.json:49](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/audit30-results.json#L49) |
| nextbase29-30 | At Nextbase SHA00ad2da857b84322ff359db098cbf1cb4f4b7282, five local-action unpinned warnings were removed; score37 to72, blocking0 to0. | [scripts/evaluation/audit30-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/audit30-results.json#L1) · [scripts/evaluation/audit30-results.json:54](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/audit30-results.json#L54) · [scripts/evaluation/audit30-results.json:56](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/audit30-results.json#L56) |
| sql-oracles | #23 records PostgreSQL16.14 authored effects: main448/448, exceptions8/8, prerequisites13/13; historical560 checks preserved, not newly executed. | [scripts/evaluation/rls-authorization23-results.json:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/rls-authorization23-results.json#L1) · [scripts/evaluation/rls-authorization23-results.json:128](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/rls-authorization23-results.json#L128) · [scripts/evaluation/rls-authorization23-results.json:131](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/scripts/evaluation/rls-authorization23-results.json#L131) |
| product33 | #33 provides real-product loopback/H2 Playwright workflow and boundary scripts using owned synthetic ZIP/accounts and worker-v40, not real target-app exploit tests. | [frontend/tests/browser/product33-live.cjs:1](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/frontend/tests/browser/product33-live.cjs#L1) · [frontend/tests/browser/product33-live.cjs:22](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/frontend/tests/browser/product33-live.cjs#L22) · [frontend/tests/browser/product33-live.cjs:23](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/frontend/tests/browser/product33-live.cjs#L23) |

실제 앱은 공식 취약·수정 쌍, 원본 정적 흐름, 자체 변형, Grade C 무정답 자료를 분리합니다. FlintCMS의 공식 수정 SHA가 있어도 전체 요청 경로가 끊겼으면 TP가 아닙니다. 이미 본 DVNA/Goof 자료는 독립 Holdout이 아닙니다. #31의 추적된 공개 실행 영수증과 #33의 추적된 결과 JSON은 확인되지 않았으며, 스크립트 존재로 실행 성공을 대체하지 않습니다.

## Finding 식별·중복 제거·비교 경계

| 채널 | 식별 형식 | 경계 | 근거 |
| --- | --- | --- | --- |
| SUPABASE_FINDING | supabase-rls:${table.scope}:${table.table} | One root-cause candidate per scope/table, roles/operations aggregated; does not identify actual exploit or app request. No source revision in ID; NOT_COMPARED means no resolved-history claim. | [analyzers/typescript/supabase.mjs:96](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/analyzers/typescript/supabase.mjs#L96) |
| DEPLOYMENT_FINDING | config: + UUID.nameUUIDFromBytes(UTF8(filePath / scope / setting / line / ruleId)) | Deduplicated same ID, capped300; stable only while identity fields unchanged. REVIEW_REQUIRED/NOT_COMPARED, no risk/score promotion. | [src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java:27](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/analysis/deployment/DeploymentGuidance.java#L27) |
| RULE_MATCH | RuleMatch has ruleId/filePath/line; later risk ID code:${vulnerabilityId} or code:index:${i} | Not the same ID scheme as deployment, Supabase, or OSV. | [src/main/java/com/securedeploy/risk/service/RiskPrioritizationEngine.java:29](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/risk/service/RiskPrioritizationEngine.java#L29) |
| SCA_ADVISORY | Upstream osvId with ecosystem/package/installedVersion; not product RuleID | 자세한 의미는 참조 구현 | [src/main/java/com/securedeploy/sca/client/OsvAdvisoryMapper.java:35](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/sca/client/OsvAdvisoryMapper.java#L35) |
| DEPENDENCY_RISK | dependency:${ecosystem} / ${packageName} / ${installedVersion} / ${canonicalAdvisoryId} | Canonical risk ID prefers CVE then GHSA. OsvAliasDeduplicator instead prefers GHSA for its raw SCA representative. | [src/main/java/com/securedeploy/risk/service/DependencyFindingCanonicalizer.java:40](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/risk/service/DependencyFindingCanonicalizer.java#L40) |
| SCA_REVIEW_REQUIREMENT | unresolved:${DependencyComponent.identity()} and coverage:sca | Requirements are not new vulnerability RuleIDs. | [src/main/java/com/securedeploy/risk/service/RiskPrioritizationEngine.java:67](https://github.com/sangwooking/SecureDeploy/blob/08eb483e22d78a59115b9045ecb45201045f8a2a/src/main/java/com/securedeploy/risk/service/RiskPrioritizationEngine.java#L67) |
## 이전 E2E 보고값 — 실행 영수증 미연결

아래는 이전 대화에서 이어받은 수치입니다. 구현·테스트 정의만 연결되어 있으므로 이번 감사에서 실행 성공을 확인한 수치가 아니며 발표의 검증 통계로 사용하지 않습니다.

| 항목 | 미검증 보고값 |
| --- | --- |
| backendTests | 759 |
| backendSkipped | 9 |
| frontendTests | 195 |
| viewports | [1440,1280,768,390,320] |
| realProductionJarAndH2 | true |
| negativeBoundaryChecks | 151 |
| manualPropertiesDebugAndStacktraceBeforeAfter | true |
| scoreBefore | 86 |
| scoreAfter | 100 |
| riskAfter | "REVIEW_REQUIRED" |
| coverageAfter | "PARTIAL" |
| unverifiedZipComparison | "NO_BASELINE" |
| resolvedCount | 0 |

- 이전 대화에서 이어받은 집계이며 연결된 공개 실행 영수증은 확인하지 못했습니다. CODE/TEST 참조는 아래 숫자의 실행 성공 증거가 아닙니다. #33.7의 검증 통계에 사용하지 않습니다.
- 같은 소스 쌍을 다섯 화면 폭에서 반복했다고 보고된 것이며 독립적인 취약점 5건이 아닙니다.
- 원본 앱 실행·정상 업무 기능·GitHub App·실제 AI Provider 검증 아님.

## 공식 기준: 관련성 ≠ 준수

| OWASP Top10:2025 | 관련 분야/미확인 |
| --- | --- |
| A01:2025 Broken Access Control | administrator, idor-bola, protected-fields-bopla, intent-boundary, rls-grants, ssrf, path, csrf, redirect |
| A02:2025 Security Misconfiguration | secret-literals, secret-response, upload, cors, docker-compose, deployment, error-logging |
| A03:2025 Software Supply Chain Failures | ci, sca |
| A04:2025 Cryptographic Failures | deployment, transport |
| A05:2025 Injection | sql, nosql, xss, command, ci, code-evaluation |
| A06:2025 Insecure Design | rate-abuse |
| A07:2025 Authentication Failures | authentication, cookie-session, jwt |
| A08:2025 Software or Data Integrity Failures | ci, deserialization |
| A09:2025 Security Logging & Alerting Failures | ci |
| A10:2025 Mishandling of Exceptional Conditions | error-logging |

| OWASP API:2023 | 관련 분야/미확인 |
| --- | --- |
| API1:2023 Broken Object Level Authorization | idor-bola, intent-boundary, rls-grants |
| API2:2023 Broken Authentication | authentication, cookie-session, jwt |
| API3:2023 Broken Object Property Level Authorization | protected-fields-bopla, intent-boundary, secret-response, rls-grants |
| API4:2023 Unrestricted Resource Consumption | upload, rate-abuse |
| API5:2023 Broken Function Level Authorization | administrator |
| API6:2023 Unrestricted Access to Sensitive Business Flows | 미지원 또는 검증 부족 |
| API7:2023 Server Side Request Forgery | ssrf |
| API8:2023 Security Misconfiguration | secret-literals, cors, docker-compose, deployment |
| API9:2023 Improper Inventory Management | 미지원 또는 검증 부족 |
| API10:2023 Unsafe Consumption of APIs | 미지원 또는 검증 부족 |

ASVS5.0.0 고정 릴리스의 **345개 요구사항 ID 전체**를 JSON에 열거했습니다. 직접 연결된 항목도 PARTIAL_RELATED이며 요구사항 충족으로 체크하지 않습니다. 나머지는 NOT_SUPPORTED_OR_NOT_VERIFIED로 명시했습니다. 검증된 ASVS 준수 항목 수는 0입니다.

- [OWASP2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- [API2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/)
- [ASVS500](https://raw.githubusercontent.com/OWASP/ASVS/5cf9b032440be53ce345ab3c130fda46ba1ce7a2/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json)
- [mongoose7](https://mongoosejs.com/docs/migrating_to_7.html): 7+ callback removal; does not validate all Mongoose versions
- [sequelize6](https://sequelize.org/docs/v6/core-concepts/raw-queries/): bind/replacements and SQL identity distinction, not actual install proof
- [next](https://nextjs.org/docs/app/getting-started/route-handlers): App route.js/ts and HTTP exports; engine bounds separately enforced
- [supabase-auth](https://supabase.com/docs/guides/auth/server-side/creating-a-client): getUser/getClaims/getSession meanings are different; static call is not authentication success
- [node-child-process](https://nodejs.org/api/child_process.html): exec shell versus default execFile contract; argument injection not proved safe

CWE는 추상화 수준을 함께 기록합니다. class-level CWE-943 같은 관련 분류를 구체적인 공격 성공 또는 CVE로 승격하지 않습니다. 구현에 없는 매핑은 감사 관련성이지 제품 변경이 아닙니다.

## Worker v28→v40 이력

| Worker | 실제 전이 커밋 | 변경 의미 |
| --- | --- | --- |
| ts-server-v28 | [2d86b3ac](https://github.com/sangwooking/SecureDeploy/commit/2d86b3acf49913e0911fbe0a4dcb4fdd0b9eebf3) | feat: distinguish declared column update privileges from row policies |
| ts-server-v29 | [8fdfb4af](https://github.com/sangwooking/SecureDeploy/commit/8fdfb4af53ae110d5f96ca7c49a610bed5dfd4a4) | feat: add bounded Mongoose query selector analysis |
| ts-server-v30 | [6f303077](https://github.com/sangwooking/SecureDeploy/commit/6f3030776aff8bab48299453690e55c0aef690f5) | feat: recognize version-aware Mongoose callback execution |
| ts-server-v31 | [9f849069](https://github.com/sangwooking/SecureDeploy/commit/9f849069cb8272bb0c1e668163c5da0b208411ed) | fix: scope request field validation and explain query risks |
| ts-server-v32 | [3bff3952](https://github.com/sangwooking/SecureDeploy/commit/3bff39521d5b26783dbc3ef99ecb625c4663a08e) | fix: preserve verified identity provenance in Supabase filters |
| ts-server-v33 | [3dddc814](https://github.com/sangwooking/SecureDeploy/commit/3dddc814e9e60f2d29b6fbd55fcef86b737f09f4) | fix: track bounded secret response objects and classify Supabase keys |
| ts-server-v34 | [32d12bd0](https://github.com/sangwooking/SecureDeploy/commit/32d12bd0e4cd9a37ef2ba2ab5e675bd32d59886f) | fix: include column update grants in RLS write review evidence |
| ts-server-v35 | [e7b0a4b6](https://github.com/sangwooking/SecureDeploy/commit/e7b0a4b6ffa0955e7f8b4cda417221dbdd40e8ab) | fix: refine Sequelize SQL objects and Mongoose selector tracing |
| ts-server-v36 | [87c7f59d](https://github.com/sangwooking/SecureDeploy/commit/87c7f59d4c946c08198cb0a7757febc8735334b1) | fix: improve bounded XSS context and SSRF destination precision |
| ts-server-v37 | [c9d2cc22](https://github.com/sangwooking/SecureDeploy/commit/c9d2cc226c0bbe8485b5ea0ccbc9913211dba50c) | feat: add bounded Node filesystem path flow analysis |
| ts-server-v38 | [794d39a7](https://github.com/sangwooking/SecureDeploy/commit/794d39a75dc8b3b7bcda76d1aa259ffd7b31b168) | feat: add bounded CORS and session response evidence |
| ts-server-v39 | [ec8157b3](https://github.com/sangwooking/SecureDeploy/commit/ec8157b3594f536803ca0f0a7bd623a3f27c1652) | feat: add bounded Express rate limiting path evidence |
| ts-server-v40 | [1aff9a23](https://github.com/sangwooking/SecureDeploy/commit/1aff9a2313b96cbcff7791bb88d8a58826e2d62d) | fix: preserve HTTP origin and invalidate replaced URL guards |

버전 번호는 analyzer.mjs의 실제 VERSION 전이 diff와 파일 해시로 확인했습니다. 버전 증가와 탐지 성능 증가를 동일시하지 않습니다. 세부 개선 수치는 해당 고정 평가 기록의 전후 셀에서만 주장할 수 있습니다.

## 재현·안전성

기준 커밋의 모든 evidence path/line/SHA256, Rule ID 실재, 중복, ASVS 번호, JSON Pointer/원래 수치, 네 문서의 상태·분모를 확인합니다. 제품 코드·Rule/Risk·API/DB/UI는 수정하지 않고 전체 빌드·앱 실행·사용자 DB 조회/변경·서버 재시작·유료 AI를 수행하지 않습니다. 원문 소스나 비공개 실행 기록은 새 공개 자료에 복사하지 않습니다.

문서 검증 결과(제품 테스트 재실행과 별개):

```json
{
  "checks": 7918,
  "ruleIds": 72,
  "evidenceAnchors": 600,
  "evaluationRecords": 75,
  "metricPointers": 17,
  "frozenEvidenceHashes": 65,
  "versionTransitions": 13,
  "asvsRequirementIds": 345,
  "cweDefinitions": 33,
  "productCodeChanges": 0,
  "fullBuildOrAnalyzerRerun": false
}
```
