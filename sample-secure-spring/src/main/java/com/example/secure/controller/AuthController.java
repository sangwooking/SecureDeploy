package com.example.secure.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final PasswordEncoder passwordEncoder;

    public AuthController(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) {
        String encodedPassword = passwordEncoder.encode(request.password());
        return ResponseEntity.ok(new AuthResponse("회원가입 요청이 안전하게 처리되었습니다.", encodedPassword.length()));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        Cookie sessionCookie = new Cookie("SESSION", "issued-by-server-side-session-store");
        sessionCookie.setSecure(true);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setPath("/");
        sessionCookie.setMaxAge(1800);
        response.addCookie(sessionCookie);

        return ResponseEntity.ok(new AuthResponse("로그인 요청이 안전하게 처리되었습니다.", request.email().length()));
    }

    public record SignupRequest(
            @Email String email,
            @NotBlank @Size(min = 12) String password,
            @NotBlank String displayName
    ) {
    }

    public record LoginRequest(
            @Email String email,
            @NotBlank String password
    ) {
    }

    public record AuthResponse(String message, int referenceLength) {
    }
}
