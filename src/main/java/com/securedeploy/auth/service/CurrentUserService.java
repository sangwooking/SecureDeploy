package com.securedeploy.auth.service;

import com.securedeploy.auth.security.AuthenticatedUser;
import com.securedeploy.global.error.SecureDeployException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class CurrentUserService {

    public Long currentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof AuthenticatedUser user)) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        }
        return user.id();
    }

    public Long currentUserIdOrNull() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof AuthenticatedUser user)) {
            return null;
        }
        return user.id();
    }
}
