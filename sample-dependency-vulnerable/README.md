# sample-dependency-vulnerable

SecureDeploy의 Dependency/CVE 후보 탐지 기능 시연을 위해 의도적으로 오래된 의존성과 위험 후보 이미지를 포함한 샘플 프로젝트입니다.

## 포함된 취약 버전 후보

### Frontend / NPM
- lodash 4.17.10
- minimist 1.2.0
- axios 0.20.0
- serialize-javascript 2.1.2

### Java / Maven
- log4j-core 2.14.1
- jackson-databind 2.9.10

### Java / Gradle
- spring-webmvc 5.3.10
- commons-collections 3.2.1

### Docker
- ubuntu:18.04
- node:latest

이 프로젝트는 실제 운영에 사용하면 안 되며, SecureDeploy 분석 테스트 전용입니다.
