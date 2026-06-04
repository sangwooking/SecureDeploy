# sample-secure-spring

SecureDeploy 시연에서 취약한 샘플 프로젝트와 비교하기 위한 정상/안전한 Spring Boot 예제입니다.

## 보안적으로 안전하게 작성한 항목

- `spring.datasource.password`는 `${DB_PASSWORD}` 환경변수 참조 방식으로 작성했습니다.
- `jwt.secret`은 `${JWT_SECRET}` 환경변수 참조 방식으로 작성했습니다.
- `debug=false`로 설정했습니다.
- Actuator는 `health,info`만 노출하고 전체 노출(`*`)을 사용하지 않습니다.
- `server.error.include-stacktrace=never`로 스택트레이스 노출을 막았습니다.
- `@CrossOrigin("*")`를 사용하지 않았습니다.
- `permitAll()`은 로그인, 회원가입, 기본 actuator 상태 확인처럼 공개가 필요한 엔드포인트에만 최소 적용했습니다.
- `createNativeQuery`, `Statement`를 사용하지 않고 Spring Data JPA Repository의 파생 쿼리를 사용했습니다.
- 쿠키는 `secure=true`, `httpOnly=true`로 설정했습니다.
- 입력값에는 Bean Validation을 적용했습니다.

## SecureDeploy 분석 예상 결과

이 프로젝트는 민감정보 하드코딩, actuator 전체 노출, 디버그 모드, 스택트레이스 노출, 위험한 SQL 사용을 피하도록 작성되었습니다.
현재 SecureDeploy 룰이 `permitAll()` 사용 자체를 탐지하므로 공개 API 허용 설정이 낮은 위험도 또는 중간 위험도로 표시될 수 있지만, 보안 점수는 높게 나오는 비교용 정상 샘플입니다.
