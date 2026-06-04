# sample-vulnerable-frontend

SecureDeploy의 React/Vite/JavaScript/TypeScript 보안 룰 시연을 위한 취약 프론트엔드 샘플입니다.
실제 운영 또는 학습용 앱 구현이 아니라, 탐지 테스트 목적으로 의도적으로 위험 패턴을 포함합니다.

## 포함된 취약 패턴

- `dangerouslySetInnerHTML` 사용
- `localStorage`에 accessToken, refreshToken, jwt 저장/조회
- `.env`에 `VITE_API_KEY`, `VITE_CLIENT_SECRET` 하드코딩
- `VITE_API_BASE_URL=http://api.example.com` 평문 API URL
- `window.location.href = next` 형태의 검증되지 않은 리다이렉트
- `package.json` scripts에 `curl`, `rm -rf` 위험 명령어
- 위험 후보 dependency `event-stream` 포함
- `vite.config.ts`에 API key 형태의 문자열 포함
