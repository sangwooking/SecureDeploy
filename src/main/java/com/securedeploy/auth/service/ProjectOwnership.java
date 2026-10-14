package com.securedeploy.auth.service;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import org.springframework.http.HttpStatus;

/** Ownerless legacy records are retained, but are not shared user data. */
public final class ProjectOwnership {
    private ProjectOwnership() { }

    public static void requireOwner(ProjectEntity project, Long userId) {
        if (userId == null) throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        if (project == null || project.getUser() == null || !userId.equals(project.getUser().getId())) {
            throw new SecureDeployException(HttpStatus.FORBIDDEN, "본인 소유 프로젝트에만 접근할 수 있습니다.");
        }
    }
}
