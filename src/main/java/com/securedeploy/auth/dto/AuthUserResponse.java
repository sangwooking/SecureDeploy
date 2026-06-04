package com.securedeploy.auth.dto;

import com.securedeploy.persistence.entity.UserEntity;

public record AuthUserResponse(
        Long id,
        String email,
        String name
) {

    public static AuthUserResponse from(UserEntity user) {
        return new AuthUserResponse(user.getId(), user.getEmail(), user.getName());
    }
}
