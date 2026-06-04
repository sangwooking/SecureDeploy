package com.securedeploy.auth.security;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.UserEntity;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final Pattern SUBJECT_PATTERN = Pattern.compile("\\\"sub\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private static final Pattern EXPIRATION_PATTERN = Pattern.compile("\\\"exp\\\"\\s*:\\s*(\\d+)");

    private final String secret;
    private final long expirationSeconds;

    public JwtTokenProvider(
            @Value("${securedeploy.jwt.secret:securedeploy-local-dev-secret-change-me}") String secret,
            @Value("${securedeploy.jwt.expiration-seconds:86400}") long expirationSeconds
    ) {
        this.secret = secret;
        this.expirationSeconds = expirationSeconds;
    }

    public String createToken(UserEntity user) {
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        long expiration = Instant.now().plusSeconds(expirationSeconds).getEpochSecond();
        String payload = "{\"sub\":\"" + user.getId() + "\",\"email\":\"" + escape(user.getEmail()) + "\",\"exp\":" + expiration + "}";
        String signingInput = base64Url(header.getBytes(StandardCharsets.UTF_8)) + "." + base64Url(payload.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + sign(signingInput);
    }

    public Long extractUserId(String token) {
        String[] parts = split(token);
        verifySignature(parts);
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        validateExpiration(payload);

        Matcher matcher = SUBJECT_PATTERN.matcher(payload);
        if (!matcher.find()) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "유효하지 않은 인증 토큰입니다.");
        }
        return Long.parseLong(matcher.group(1));
    }

    private String[] split(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "유효하지 않은 인증 토큰입니다.");
        }
        return parts;
    }

    private void verifySignature(String[] parts) {
        String signingInput = parts[0] + "." + parts[1];
        String expectedSignature = sign(signingInput);
        if (!constantTimeEquals(expectedSignature, parts[2])) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "유효하지 않은 인증 토큰입니다.");
        }
    }

    private void validateExpiration(String payload) {
        Matcher matcher = EXPIRATION_PATTERN.matcher(payload);
        if (!matcher.find()) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "유효하지 않은 인증 토큰입니다.");
        }
        long expiration = Long.parseLong(matcher.group(1));
        if (Instant.now().getEpochSecond() > expiration) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "인증 토큰이 만료되었습니다. 다시 로그인해 주세요.");
        }
    }

    private String sign(String signingInput) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return base64Url(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new SecureDeployException(HttpStatus.INTERNAL_SERVER_ERROR, "인증 토큰 처리 중 오류가 발생했습니다.");
        }
    }

    private String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private boolean constantTimeEquals(String left, String right) {
        return MessageDigestHolder.equals(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static class MessageDigestHolder {
        private static boolean equals(byte[] left, byte[] right) {
            return java.security.MessageDigest.isEqual(left, right);
        }
    }
}
