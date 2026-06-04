# sample-vulnerable-spring

SecureDeploy 시연을 위한 의도적으로 취약한 Spring Boot 샘플 프로젝트입니다.

> 이 프로젝트는 보안 분석 도구 시연용입니다. 실제 서비스 코드로 사용하면 안 됩니다.

## 포함된 취약점

1. `application.yml`에 `spring.datasource.password` 하드코딩
2. `jwt.secret` 값 하드코딩 및 짧은 secret 사용
3. `debug=true` 설정
4. `management.endpoints.web.exposure.include=*` 설정으로 Actuator 전체 노출
5. `server.error.include-stacktrace=always` 설정으로 stacktrace 노출
6. `@CrossOrigin("*")` 사용
7. Spring Security 설정에서 `permitAll()` 사용
8. `EntityManager#createNativeQuery` 사용 및 문자열 결합 SQL
9. `Statement` / `createStatement` 사용
10. `server.servlet.session.cookie.secure=false`, `http-only=false` 쿠키 설정

## SecureDeploy 시연 방법

1. 이 폴더를 ZIP으로 압축합니다.
2. SecureDeploy 프론트엔드에서 ZIP 업로드 분석을 선택합니다.
3. 생성한 ZIP 파일을 업로드합니다.
4. 취약점 목록에서 위 항목들이 탐지되는지 확인합니다.

예시:

```bash
zip -r sample-vulnerable-spring.zip sample-vulnerable-spring
```
