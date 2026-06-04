package com.securedeploy.auth.service;

import com.securedeploy.auth.dto.AuthResponse;
import com.securedeploy.auth.dto.AuthUserResponse;
import com.securedeploy.auth.dto.LoginRequest;
import com.securedeploy.auth.dto.SignupRequest;
import com.securedeploy.auth.security.JwtTokenProvider;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.UserEntity;
import com.securedeploy.persistence.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Transactional
    public AuthResponse signup(SignupRequest request) {
        String email = normalizeEmail(request.email());
        if (userRepository.existsByEmail(email)) {
            throw new SecureDeployException(HttpStatus.CONFLICT, "이미 가입된 이메일입니다.");
        }

        UserEntity user = userRepository.save(new UserEntity(
                email,
                passwordEncoder.encode(request.password()),
                request.name().strip()
        ));
        return AuthResponse.bearer(jwtTokenProvider.createToken(user), AuthUserResponse.from(user));
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        UserEntity user = userRepository.findByEmail(normalizeEmail(request.email()))
                .orElseThrow(() -> new SecureDeployException(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 올바르지 않습니다."));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        return AuthResponse.bearer(jwtTokenProvider.createToken(user), AuthUserResponse.from(user));
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.strip().toLowerCase();
    }
}
