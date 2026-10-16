package com.securedeploy.github.app;

import com.securedeploy.persistence.repository.UserRepository;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class GitHubConnectionService {
    private static final Logger log = LoggerFactory.getLogger(GitHubConnectionService.class);
    private record Pending(long userId, String sessionHash, String verifier, Instant expiresAt) { }
    private final Map<String, Pending> pending = new HashMap<>();
    private final Object[] locks = java.util.stream.IntStream.range(0, 64).mapToObj(i -> new Object()).toArray();
    private final GitHubAppProperties properties;
    private final GitHubConnectionRepository connections;
    private final UserRepository users;
    private final GitHubTokenCipher cipher;
    private final GitHubAppClient client;
    private final java.time.Clock clock;
    @org.springframework.beans.factory.annotation.Autowired
    public GitHubConnectionService(GitHubAppProperties properties, GitHubConnectionRepository connections,
            UserRepository users, GitHubTokenCipher cipher, GitHubAppClient client) {
        this(properties, connections, users, cipher, client, java.time.Clock.systemUTC());
    }
    GitHubConnectionService(GitHubAppProperties properties, GitHubConnectionRepository connections,
            UserRepository users, GitHubTokenCipher cipher, GitHubAppClient client, java.time.Clock clock) {
        this.properties = properties; this.connections = connections; this.users = users; this.cipher = cipher; this.client = client;
        this.clock = clock;
    }
    public GitHubAppDtos.ConnectionStatus status(long userId) {
        boolean configured;
        try { properties.requireConfigured(); configured = true; } catch (GitHubAppException absent) { configured = false; }
        var connection = connections.findById(userId).orElse(null);
        boolean expired = connection != null && !connection.getExpiresAt().isAfter(Instant.now(clock).plusSeconds(30));
        return new GitHubAppDtos.ConnectionStatus(configured, connection != null && !expired, expired,
                connection == null ? null : connection.getGithubLogin(), connection == null ? null : connection.getExpiresAt(),
                configured ? "https://github.com/apps/" + properties.getSlug() + "/installations/new" : null);
    }
    public GitHubAppDtos.Authorization begin(long userId, String session) {
        properties.requireConfigured();
        String state = random(), verifier = random();
        synchronized (pending) {
            pending.entrySet().removeIf(e -> !e.getValue().expiresAt().isAfter(Instant.now(clock)) || e.getValue().userId() == userId);
            if (pending.size() >= 1000) throw new GitHubAppException(HttpStatus.TOO_MANY_REQUESTS, "연결 요청이 많습니다. 잠시 후 다시 시도해 주세요.");
            pending.put(state, new Pending(userId, hash(session), verifier, Instant.now(clock).plusSeconds(300)));
        }
        return new GitHubAppDtos.Authorization("https://github.com/login/oauth/authorize?client_id=" + url(properties.getClientId())
                + "&redirect_uri=" + url(properties.getCallbackUrl()) + "&state=" + state
                + "&code_challenge=" + hash(verifier) + "&code_challenge_method=S256&prompt=select_account");
    }
    public GitHubAppDtos.ConnectionStatus complete(long userId, String session, GitHubAppDtos.Callback callback) {
        properties.requireConfigured();
        synchronized (lock(userId)) {
            Pending attempt;
            synchronized (pending) {
                attempt = pending.get(callback.state());
                if (attempt == null || attempt.userId() != userId || !attempt.expiresAt().isAfter(Instant.now(clock))
                        || !MessageDigest.isEqual(attempt.sessionHash().getBytes(StandardCharsets.US_ASCII), hash(session).getBytes(StandardCharsets.US_ASCII))) {
                    log.warn("GitHub callback stage=STATE_SESSION_CHECK outcome=REJECTED");
                    throw new GitHubAppException(HttpStatus.BAD_REQUEST, "GitHub 연결 요청이 만료되었거나 시작한 로그인 세션과 다릅니다. 다시 연결해 주세요.");
                }
                pending.remove(callback.state());
            }
            log.info("GitHub callback stage=STATE_SESSION_CHECK outcome=SUCCESS");
            var response = client.exchange(callback.code(), attempt.verifier());
            String token = response.path("access_token").asText();
            long seconds = response.path("expires_in").asLong();
            if (token.isBlank() || response.hasNonNull("error")) throw GitHubAppException.authenticationFailed();
            boolean saved = false;
            try {
                if (seconds <= 0 || seconds > 28800) {
                    log.warn("GitHub callback stage=TOKEN_EXPIRY_CHECK outcome=REJECTED");
                    throw new GitHubAppException(HttpStatus.CONFLICT,
                            "GitHub App의 만료되는 사용자 토큰 설정을 활성화한 뒤 다시 연결해 주세요.");
                }
                var github = client.user(token);
                long githubId = github.path("id").asLong();
                String login = github.path("login").asText();
                if (githubId <= 0 || !login.matches("[a-zA-Z0-9-]{1,100}")) throw GitHubAppException.unavailable();
                var old = connections.findById(userId).orElse(null);
                String previousCiphertext = old == null ? null : old.getEncryptedAccessToken();
                if (old != null && old.getGithubUserId() != githubId) throw new GitHubAppException(HttpStatus.CONFLICT,
                        "다른 GitHub 계정이 연결되어 있습니다. 기존 연결을 해제한 뒤 새 계정을 연결해 주세요.");
                var user = users.findById(userId).orElseThrow(GitHubAppException::reconnect);
                String encrypted;
                try { encrypted = cipher.encrypt(userId, token); }
                catch (RuntimeException failure) {
                    log.warn("GitHub callback stage=TOKEN_ENCRYPTION outcome=FAILED");
                    throw failure;
                }
                try {
                    connections.saveAndFlush(new GitHubConnectionEntity(user, githubId, login, encrypted, Instant.now(clock).plusSeconds(seconds)));
                } catch (RuntimeException failure) {
                    log.warn("GitHub callback stage=CONNECTION_SAVE outcome=FAILED");
                    throw failure;
                }
                saved = true;
                log.info("GitHub callback stage=CONNECTION_SAVE outcome=SUCCESS");
                if (old != null) {
                    try { String previous = cipher.decrypt(userId, previousCiphertext); if (!previous.equals(token)) client.revokeUser(previous); }
                    catch (GitHubAppException ignored) { }
                }
                return status(userId);
            } finally { if (!saved) client.revokeUser(token); }
        }
    }
    public String disconnect(long userId) {
        synchronized (lock(userId)) {
            synchronized (pending) { pending.entrySet().removeIf(e -> e.getValue().userId() == userId); }
            var connection = connections.findById(userId).orElse(null);
            connections.deleteById(userId);
            boolean revoked = true;
            if (connection != null) {
                try { revoked = client.revokeUser(cipher.decrypt(userId, connection.getEncryptedAccessToken())); }
                catch (RuntimeException unavailable) { revoked = false; }
            }
            return revoked ? "GitHub 연결을 해제했습니다. 기존 분석 이력은 유지됩니다."
                    : "서버의 GitHub 연결을 삭제했습니다. GitHub 토큰 회수는 확인하지 못했으므로 GitHub Settings의 Authorized GitHub Apps에서도 권한을 해제해 주세요.";
        }
    }
    public GitHubAppDtos.InstallationPage installations(long userId, int page) {
        return client.installations(accessToken(userId), page);
    }
    public GitHubAppDtos.RepositoryPage repositories(long userId, long installation, int page) {
        return client.repositories(accessToken(userId), installation, page);
    }
    public GitHubAppDtos.Repository authorize(long userId, long installation, long repository) {
        return client.authorizeRepository(accessToken(userId), installation, repository);
    }
    private String accessToken(long userId) {
        properties.requireConfigured();
        var connection = connections.findById(userId).orElseThrow(() -> new GitHubAppException(HttpStatus.CONFLICT, "GitHub 계정 연결이 필요합니다. 계정에서 GitHub를 연결해 주세요."));
        if (!connection.getExpiresAt().isAfter(Instant.now(clock).plusSeconds(60))) throw GitHubAppException.reconnect();
        return cipher.decrypt(userId, connection.getEncryptedAccessToken());
    }
    private Object lock(long userId) { return locks[Math.floorMod(Long.hashCode(userId), locks.length)]; }
    private String random() { byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    private String url(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private String hash(String value) {
        if (value == null || value.isBlank()) throw GitHubAppException.reconnect();
        try { return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
