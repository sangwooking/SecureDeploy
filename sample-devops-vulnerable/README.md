# sample-devops-vulnerable

SecureDeploy의 Docker / DevOps / 배포 설정 보안 분석을 시연하기 위한 취약 샘플입니다.
실제 운영 배포용이 아니라, 탐지 테스트를 위해 의도적으로 위험한 설정을 포함합니다.

## 포함된 취약 설정

- Dockerfile에서 `FROM node:latest` 사용
- Dockerfile에 `ENV API_KEY`, `ENV SECRET`, `ENV PASSWORD` 하드코딩
- Dockerfile에 `USER` 지시어가 없어 root 실행 가능성 존재
- docker-compose에서 `privileged: true` 사용
- docker-compose에서 `network_mode: host` 사용
- docker-compose에서 `postgres:latest` 사용
- GitHub Actions에서 `actions/checkout@main`, `docker/login-action@master` 사용
- GitHub Actions에서 `curl ... | sh` 사용
- GitHub Actions에서 `${{ secrets.* }}` echo 출력
- Nginx `autoindex on;`
- Nginx `server_tokens on;`
- Nginx HTTP listen만 존재하고 HTTPS redirect 없음
- Kubernetes `privileged: true`
- Kubernetes `image: nginx:latest`
- Kubernetes Service `type: NodePort`
- Kubernetes Secret에 평문 비밀값으로 보이는 항목 포함
