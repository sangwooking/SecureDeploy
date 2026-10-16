package com.securedeploy.github.app;

import com.securedeploy.global.error.SecureDeployException;
import org.springframework.http.HttpStatus;

public class GitHubAppException extends SecureDeployException {
    public GitHubAppException(HttpStatus status, String message) { super(status, message); }
    public static GitHubAppException notConfigured() {
        return new GitHubAppException(HttpStatus.SERVICE_UNAVAILABLE, "GitHub App 설정이 아직 준비되지 않았습니다. 공개 URL 또는 ZIP 분석을 이용해 주세요.");
    }
    public static GitHubAppException reconnect() {
        return new GitHubAppException(HttpStatus.CONFLICT, "GitHub 인증이 만료되었거나 해제되었습니다. 계정에서 GitHub를 다시 연결해 주세요.");
    }
    public static GitHubAppException denied() {
        return new GitHubAppException(HttpStatus.FORBIDDEN, "선택한 저장소에 접근할 수 없습니다. GitHub 사용자 권한과 App 설치·승인 범위를 확인해 주세요.");
    }
    public static GitHubAppException unavailable() {
        return new GitHubAppException(HttpStatus.BAD_GATEWAY, "GitHub 요청을 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.");
    }
    public static GitHubAppException authenticationFailed() {
        return new GitHubAppException(HttpStatus.BAD_GATEWAY,
                "GitHub 연결 인증을 완료하지 못했습니다. 계정에서 다시 연결해 주세요. 반복되면 관리자에게 문의해 주세요.");
    }
    public static GitHubAppException appAuthenticationFailed() {
        return new GitHubAppException(HttpStatus.SERVICE_UNAVAILABLE,
                "GitHub App 인증 설정을 확인해야 합니다. 관리자에게 문의해 주세요.");
    }
    public static GitHubAppException rateLimited() {
        return new GitHubAppException(HttpStatus.TOO_MANY_REQUESTS,
                "GitHub 요청 한도에 도달했습니다. 잠시 후 다시 시도해 주세요.");
    }
}
