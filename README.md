# SecureDeploy

AI 기반 Full-Stack DevSecOps 보안 분석 및 프로젝트 보안 관리 플랫폼

## 프로젝트 소개

SecureDeploy는 개발자가 실제 서비스 배포 전에  
프로젝트 전반의 보안 상태를 분석하고 관리할 수 있도록 설계된 AI 기반 DevSecOps 보안 플랫폼입니다.

단순히 코드 한 줄의 취약점만 탐지하는 것이 아니라:

- 백엔드(Spring Boot)
- 프론트엔드(React/Vite)
- Docker / Kubernetes
- GitHub Actions(CI/CD)
- Nginx
- Dependency / 라이브러리 버전
- AI 기반 보안 리뷰 및 개선 전략

까지 함께 분석하여 실제 개발 및 배포 환경에서 발생할 수 있는 보안 위험을 통합적으로 진단합니다.

---

# 핵심 목표

실제 보안 사고는 단순 코드 실수뿐 아니라 다음 영역에서도 자주 발생합니다.

- 인증/인가 설정 문제
- 프론트엔드 XSS 위험
- localStorage 토큰 저장
- Docker root 실행
- Kubernetes privileged container
- CI/CD secret 노출
- 오래된 라이브러리 버전(Log4Shell 등)
- 배포 설정 실수
- 공급망(Dependency) 공격

SecureDeploy는 이러한 실제 DevSecOps 환경의 위험 요소를 통합적으로 분석하는 것을 목표로 합니다.

---

# 주요 기능

## 1. Backend Security Analysis

Spring Boot / Java 기반 프로젝트 분석 지원

탐지 예시:

- permitAll 과다 사용
- JWT secret 하드코딩
- CORS 전체 허용
- Actuator 노출
- Debug 설정 활성화
- Stacktrace 노출
- 민감정보 하드코딩
- SecurityConfig 설정 문제

---

## 2. Frontend Security Analysis

React / Vite / JavaScript / TypeScript 분석 지원

탐지 예시:

- dangerouslySetInnerHTML 사용
- localStorage JWT 저장
- API Key 하드코딩
- insecure HTTP API URL
- redirect 파라미터 검증 누락
- 위험 package.json script
- 클라이언트 환경변수 노출

---

## 3. DevOps / Deployment Security Analysis

Docker / Kubernetes / GitHub Actions / Nginx 분석 지원

탐지 예시:

### Docker
- root user 실행
- latest image 사용
- secret ENV 하드코딩
- privileged container
- host network 사용

### GitHub Actions
- unpinned action
- secret echo
- curl | sh 실행

### Kubernetes
- privileged container
- latest image
- NodePort 외부 노출
- plaintext secret 의심값

### Nginx
- autoindex on
- server_tokens on
- HTTP only 설정

---

## 4. Dependency / CVE Candidate Analysis

외부 라이브러리 및 Docker base image 버전 분석 지원

탐지 예시:

### NPM
- lodash < 4.17.21
- axios < 0.21.1
- minimist < 1.2.6
- serialize-javascript < 3.1.0

### Java
- log4j-core < 2.17.1
- jackson-databind 취약 버전
- spring-webmvc 구버전

### Docker
- ubuntu:18.04
- node:latest
- nginx:latest

---

# AI 기능

SecureDeploy는 Rule Engine 기반 분석 위에 AI 기반 보안 해석 계층을 추가했습니다.

중요:
AI는 직접 취약점을 “확정 탐지”하지 않습니다.

## 구조

```text
Rule Engine
→ 1차 확정 탐지

AI
→ 해석 / 우선순위 / 개선 전략 / 보조 진단
```

---

## AI Review

취약점별:
- 위험 설명
- 공격 시나리오
- 수정 방법
- 우선순위

생성

---

## AI Summary

프로젝트 전체:
- 보안 상태
- 위험 영역
- 배포 적합성
- 우선 조치 항목

분석

---

## AI Remediation

취약점별:
- before / after 코드 예시
- 설정 개선 예시
- 보안 설정 권장안

제공

---

## AI Security Audit

Rule Engine이 놓칠 수 있는:
- 인증 흐름
- 권한 구조
- 계층 간 검증
- 예외 처리
- 배포 구조 위험

등을 보조 진단

주의:
AI Audit은 “확정 취약점”이 아니라 추가 검토 의견입니다.

---

## AI Priority / Roadmap

AI가:
- 무엇을 먼저 수정해야 하는지
- 어떤 위험이 가장 큰지
- 배포 전에 무엇을 확인해야 하는지

우선순위와 개선 로드맵 형태로 제안합니다.

---

# 프로젝트 관리 기능

SecureDeploy는 단발성 분석 도구가 아니라  
프로젝트 기반 보안 관리 플랫폼 구조를 목표로 합니다.

지원 기능:

- 회원가입 / 로그인 / JWT 인증
- 프로젝트별 분석 이력 관리
- 재분석 비교
- 해결된 취약점 추적
- 신규 취약점 추적
- 취약점 상태 관리
- 프로젝트 보안 대시보드

---

# 재분석 비교 기능

같은 프로젝트의 최신 분석 결과와 이전 분석 결과를 비교합니다.

비교 항목:

- 보안 점수 변화
- 취약점 개수 변화
- 해결된 취약점
- 신규 취약점
- 지속 취약점

---

# 취약점 상태 관리

각 취약점 상태 관리 지원:

- UNCHECKED
- ACKNOWLEDGED
- IN_PROGRESS
- RESOLVED
- IGNORED

프로젝트별 해결률 및 진행률 확인 가능

---

# 탐지 근거

SecureDeploy의 Rule Engine은 다음 기준을 기반으로 설계되었습니다.

- OWASP
- CWE
- CVE
- Spring Security Best Practices
- Docker Security Best Practices
- Kubernetes Security Recommendations
- 실제 보안 사고 사례
- DevSecOps 보안 가이드

예시:

| 탐지 항목 | 근거 |
|---|---|
| dangerouslySetInnerHTML | OWASP XSS 위험 |
| localStorage JWT 저장 | XSS 기반 토큰 탈취 위험 |
| Docker root 실행 | Container escape 위험 |
| latest image 사용 | 재현 불가능한 배포 위험 |
| log4j-core 2.14.1 | Log4Shell 계열 위험 |

---

# 분석 구조

## 전체 흐름

```text
ZIP 업로드 / GitHub Repository 입력
↓
Project Scanner
↓
Rule Engine 기반 1차 분석
↓
Vulnerability 저장
↓
AI Review / Summary / Audit 생성
↓
Project Dashboard 반영
↓
재분석 비교 및 상태 관리
```

---

# 기술 스택

## Backend
- Java
- Spring Boot
- Spring Security
- JPA / Hibernate
- PostgreSQL

## Frontend
- React
- TypeScript
- Vite

## AI
- OpenAI API
- Template AI Fallback Provider

---

# 보안 고려 사항

- API Key 하드코딩 금지
- OPENAI_API_KEY 환경변수 사용
- JWT Secret 환경변수 사용
- 민감정보 masking 처리
- AI Audit snippet 길이 제한
- 전체 프로젝트 코드 외부 전송 금지
- 제한된 snippet 기반 AI Audit 수행

---

# 향후 목표

- OSV / NVD 연동
- Docker image CVE 연동
- URL 기반 공개 보안 진단
- GitHub PR 분석
- 조직/팀 협업 기능
- 실시간 CI/CD 연동
- 자동 재분석 및 보안 리포트

---

# 결론

SecureDeploy는 단순 취약점 탐지기를 넘어:

```text
코드
프론트엔드
배포 환경
CI/CD
Dependency
AI 기반 보안 전략
```

까지 통합적으로 분석하고 관리하는  
AI 기반 Full-Stack DevSecOps 보안 관리 플랫폼을 목표로 합니다.
