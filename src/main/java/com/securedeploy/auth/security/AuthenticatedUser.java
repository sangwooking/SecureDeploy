package com.securedeploy.auth.security;

public record AuthenticatedUser(
        Long id,
        String email,
        String name
) {
}
