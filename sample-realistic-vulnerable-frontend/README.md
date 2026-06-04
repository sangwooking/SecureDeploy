# sample-realistic-vulnerable-frontend

SecureDeploy의 React/Vite/TypeScript 프론트엔드 보안 분석을 시연하기 위해 만든 현실적인 취약 샘플입니다.
단순 취약 코드 모음이 아니라, 로그인/대시보드/프로필/공지/설정 화면을 가진 관리자 대시보드 형태로 구성되어 있습니다.

> 이 프로젝트는 실제 서비스 구현 예제가 아니라 SecureDeploy 탐지 테스트를 위해 의도적으로 취약하게 작성되었습니다.

## 앱 구성

- 로그인 화면
- 관리자 대시보드 화면
- 사용자 프로필 화면
- 공지/게시글 목록 및 상세 화면
- 설정 화면
- API client 및 auth service 계층

## 의도적으로 포함된 취약 패턴

1. 로그인 성공 후 `localStorage.setItem("accessToken", token)` 사용
2. API client에서 `localStorage.getItem("accessToken")`으로 토큰을 읽어 Authorization header에 사용
3. 공지 상세에서 `dangerouslySetInnerHTML`로 HTML 공지 내용 렌더링
4. `.env`에 `VITE_API_KEY` 하드코딩
5. `.env`에 `VITE_API_BASE_URL=http://api.example.com` 사용
6. 설정 화면에서 `redirectUrl` 파라미터 기반 `window.location.href` 이동
7. `package.json` scripts에 `curl`, `rm -rf` 위험 명령 예시 포함
8. `package.json` dependencies에 위험 후보 `event-stream` 포함
9. `vite.config.ts`에 API key 형태 문자열 포함
10. TypeScript 코드 내부에 token, secret, api key 형태 문자열 포함

SecureDeploy에 ZIP 업로드하면 프론트엔드 보안 룰이 여러 개 탐지되도록 구성되어 있습니다.
