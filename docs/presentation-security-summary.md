# 졸업 발표용 보안 엔진 요약

기준 소스: `08eb483e22d78a59115b9045ecb45201045f8a2a` · 감사일: 2026-10-28 · Worker v40 / RLS v4 / Deployment v2.

이 자료는 비블라인드 소스·근거 감사입니다. 새 취약점 탐지 성과는 **0건**이며, 독립 평가·운영 안전·모든 CWE/프레임워크 지원을 주장하지 않습니다.

## 한 문장

SecureDeploy는 코드를 실행하지 않고 제한된 요청·값 전달·위험 작업과 설정·의존성 근거를 분석하고, 사용자가 내용을 이해해 편집·Diff·승인·재검사하도록 돕는 보안 분석·수정 플랫폼입니다.

## 한눈에 보는 지원 수준

| 분야 | 공식 체크 상태 | 표현 가능한 수준 |
| --- | --- | --- |
| 인증 검사 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 관리자 접근 | 부분 지원 | 선언·관찰 또는 평가 전용; 전체 취약점 탐지 아님 |
| 사용자별 객체 접근 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 보호 필드 변경 | 부분 지원 | 선언·관찰 또는 평가 전용; 전체 취약점 탐지 아님 |
| 명시적 보안 요구사항(평가 전용) | 미지원 또는 검증 부족 | 선언·관찰 또는 평가 전용; 전체 취약점 탐지 아님 |
| 고정 비밀정보·공개 키 구분 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 서버 비밀정보 응답·로그 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| Supabase RLS·GRANT | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| SQL Injection | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| NoSQL Injection | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| HTML·DOM·XSS 문맥 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 외부 URL·SSRF | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| OS Command Injection | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 파일 경로·Path Traversal | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 업로드 파일 보안 | 미지원 또는 검증 부족 | 선언·관찰 또는 평가 전용; 전체 취약점 탐지 아님 |
| CORS | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| CSRF 문맥 | 부분 지원 | 선언·관찰 또는 평가 전용; 전체 취약점 탐지 아님 |
| Cookie·Session | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 요청 제한·API 자원 남용 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| Docker·Compose | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| GitHub Actions·CI/CD | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 의존성 SCA | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 서버·배포·Nginx·Kubernetes | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 동적 코드 실행 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 위험한 역직렬화 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| JWT 키·검증 사용 문맥 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 오류 상세·타임아웃 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 외부 redirect 목적지 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |
| 평문 API URL 선언 | 부분 지원 | 선택된 Rule/구조 계약과 위험·정상 대조 근거 |

집계: Finding Rule ID 72개, 상위 분석 패스6개, 분야29개. 이 숫자는 지원 CWE 수·실전 탐지율·인증 항목 수가 아닙니다.

## 발표에서 보여줄 수 있는 증거

- DVNA·Goof의 일부 정적으로 연결된 SQL/명령/검색 조건 경로. 교육용 앱이며 실제 공격이나 별도 공식 수정 쌍의 독립 검증은 아닙니다.
- 고정 Grade B 평가에서 #30 SSRF22개: TP9/FP0/FN3/TN6/UNKNOWN4. 전체 제품 정확도가 아니며 다른 집합과 합치지 않습니다.
- 같은 작성자의 XSS21개에는 FP1, Path33개에는 FN6, Rate32개에는 FN7이 남았습니다. 미지원·정상 대조 미완료도 별도로 표시합니다.
- Supabase는 행 USING/WITH CHECK와 컬럼 UPDATE 권한·신원/쓰기 값 근거를 분리합니다. 격리 PostgreSQL 통제 결과는 실제 운영 Supabase 권한 검증이 아닙니다.
- 제품 E2E에는 합성 .properties 수정, JAR/H2 재검사, Diff/ZIP/Patch·접근통제를 검사하는 테스트 정의가 있습니다. 이전 대화의 실행 집계는 연결된 공개 영수증이 없어 이번 감사에서 미검증으로 분리했습니다. 발표 시 실행 증거가 필요한 시연은 별도 확인해야 합니다.

## 시연 순서

1. 지원 Source와 위험 작업의 파일·위치를 확인합니다. 높은 Confidence가 실제 공격 성공을 뜻하지 않음을 설명합니다.
2. Risk 판단, 규칙 기반 참고 점수, Coverage, SCA 상태를 각각 읽습니다. 100점/PARTIAL은 전체 안전이 아닙니다.
3. 지원하면 제한적 결정적 수정 또는 수동 편집을 사용하고 Diff·정상 필드·기능 영향을 검토한 뒤 승인합니다.
4. 고정 revision을 STANDARD로 재검사하고 관찰된 변화와 비교 가능 범위를 확인합니다. 구조 후보의 사라짐은 자동 RESOLVED가 아닙니다.

## 주장하면 안 되는 내용

- 모든 웹사이트/모든 OWASP·ASVS/CWE, 전체 인증·인가·파일 업로드·ORM을 지원한다.
- 일반 프로젝트의 무경고나 높은 점수가 안전을 증명한다.
- 정적 경로, 라이브러리 선언, RLS SQL이 실제 실행·인증 성공·운영 적용을 증명한다.
- 이미 본/직접 만든 자료가 외부 독립 Holdout이다. 서로 다른 평가를 더해 전체 탐지율을 계산한다.
- 공통 편집기 또는 Mock Provider가 모든 취약점의 자동 수정·실제 모델 품질·정상 기능 유지를 보장한다.

## 기술 발전 (28→40)

| 버전 | 구체적인 변화 | 근거 커밋 |
| --- | --- | --- |
| ts-server-v28 | feat: distinguish declared column update privileges from row policies | [2d86b3ac](https://github.com/sangwooking/SecureDeploy/commit/2d86b3acf49913e0911fbe0a4dcb4fdd0b9eebf3) |
| ts-server-v29 | feat: add bounded Mongoose query selector analysis | [8fdfb4af](https://github.com/sangwooking/SecureDeploy/commit/8fdfb4af53ae110d5f96ca7c49a610bed5dfd4a4) |
| ts-server-v30 | feat: recognize version-aware Mongoose callback execution | [6f303077](https://github.com/sangwooking/SecureDeploy/commit/6f3030776aff8bab48299453690e55c0aef690f5) |
| ts-server-v31 | fix: scope request field validation and explain query risks | [9f849069](https://github.com/sangwooking/SecureDeploy/commit/9f849069cb8272bb0c1e668163c5da0b208411ed) |
| ts-server-v32 | fix: preserve verified identity provenance in Supabase filters | [3bff3952](https://github.com/sangwooking/SecureDeploy/commit/3bff39521d5b26783dbc3ef99ecb625c4663a08e) |
| ts-server-v33 | fix: track bounded secret response objects and classify Supabase keys | [3dddc814](https://github.com/sangwooking/SecureDeploy/commit/3dddc814e9e60f2d29b6fbd55fcef86b737f09f4) |
| ts-server-v34 | fix: include column update grants in RLS write review evidence | [32d12bd0](https://github.com/sangwooking/SecureDeploy/commit/32d12bd0e4cd9a37ef2ba2ab5e675bd32d59886f) |
| ts-server-v35 | fix: refine Sequelize SQL objects and Mongoose selector tracing | [e7b0a4b6](https://github.com/sangwooking/SecureDeploy/commit/e7b0a4b6ffa0955e7f8b4cda417221dbdd40e8ab) |
| ts-server-v36 | fix: improve bounded XSS context and SSRF destination precision | [87c7f59d](https://github.com/sangwooking/SecureDeploy/commit/87c7f59d4c946c08198cb0a7757febc8735334b1) |
| ts-server-v37 | feat: add bounded Node filesystem path flow analysis | [c9d2cc22](https://github.com/sangwooking/SecureDeploy/commit/c9d2cc226c0bbe8485b5ea0ccbc9913211dba50c) |
| ts-server-v38 | feat: add bounded CORS and session response evidence | [794d39a7](https://github.com/sangwooking/SecureDeploy/commit/794d39a75dc8b3b7bcda76d1aa259ffd7b31b168) |
| ts-server-v39 | feat: add bounded Express rate limiting path evidence | [ec8157b3](https://github.com/sangwooking/SecureDeploy/commit/ec8157b3594f536803ca0f0a7bd623a3f27c1652) |
| ts-server-v40 | fix: preserve HTTP origin and invalidate replaced URL guards | [1aff9a23](https://github.com/sangwooking/SecureDeploy/commit/1aff9a2313b96cbcff7791bb88d8a58826e2d62d) |

다음 과제는 무조건 Rule 수를 늘리는 것이 아니라 남은 실제 요청 연결 공백, 알려진 FP/FN, 독립 정답 검토와 수정 후 정상 동작 근거를 강화하는 것입니다. [전체 체크리스트](security-capabilities.md) · [상세 근거와 평가 분모](security-rule-evidence.md) · [JSON 원장](security-capabilities.json).
