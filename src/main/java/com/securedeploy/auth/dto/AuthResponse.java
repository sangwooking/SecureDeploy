package com.securedeploy.auth.dto;

public record AuthResponse(
        String accessToken,
        String tokenType,
        AuthUserResponse user
) {

    public static AuthResponse bearer(String accessToken, AuthUserResponse user) {
        return new AuthResponse(accessToken, "Bearer", user);
    }
}
