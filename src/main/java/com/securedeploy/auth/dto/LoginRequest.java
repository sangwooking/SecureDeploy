package com.securedeploy.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @Email(message = "올바른 이메일 형식이어야 합니다.")
        @NotBlank(message = "이메일을 입력해 주세요.")
        String email,
        @NotBlank(message = "비밀번호를 입력해 주세요.")
        String password
) {
}
