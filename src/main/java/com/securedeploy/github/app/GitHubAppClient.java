package com.securedeploy.github.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.github.model.GitHubRepositoryUrl;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/** Fixed GitHub endpoints only. Remote bodies, headers and tokens are never logged. */
@Component
public class GitHubAppClient {
    private static final Logger log = LoggerFactory.getLogger(GitHubAppClient.class);
    private enum Operation { TOKEN_EXCHANGE, USER_IDENTITY, USER_ACCESS, APP_ACCESS, TOKEN_REVOCATION }
    private enum OAuthError {
        INCORRECT_CLIENT_CREDENTIALS, REDIRECT_URI_MISMATCH, BAD_VERIFICATION_CODE,
        ACCESS_DENIED, UNVERIFIED_USER_EMAIL, UNKNOWN;

        static OAuthError from(String value) {
            return switch (value) {
                case "incorrect_client_credentials" -> INCORRECT_CLIENT_CREDENTIALS;
                case "redirect_uri_mismatch" -> REDIRECT_URI_MISMATCH;
                case "bad_verification_code" -> BAD_VERIFICATION_CODE;
                case "access_denied" -> ACCESS_DENIED;
                case "unverified_user_email" -> UNVERIFIED_USER_EMAIL;
                default -> UNKNOWN;
            };
        }
        GitHubAppException failure() {
            return switch (this) {
                case INCORRECT_CLIENT_CREDENTIALS -> GitHubAppException.appAuthenticationFailed();
                case REDIRECT_URI_MISMATCH -> new GitHubAppException(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE,
                        "GitHub 연결의 복귀 주소 설정이 맞지 않습니다. 관리자에게 문의해 주세요.");
                case BAD_VERIFICATION_CODE -> new GitHubAppException(org.springframework.http.HttpStatus.BAD_REQUEST,
                        "GitHub 승인 코드를 확인하지 못했습니다. 이전 화면을 새로고침하지 말고 계정에서 연결을 다시 시작해 주세요.");
                case ACCESS_DENIED -> new GitHubAppException(org.springframework.http.HttpStatus.BAD_REQUEST,
                        "GitHub 연결이 승인되지 않았습니다. 계정에서 다시 연결해 주세요.");
                case UNVERIFIED_USER_EMAIL -> new GitHubAppException(org.springframework.http.HttpStatus.BAD_REQUEST,
                        "GitHub 계정의 기본 이메일 인증을 완료한 뒤 다시 연결해 주세요.");
                case UNKNOWN -> GitHubAppException.authenticationFailed();
            };
        }
    }
    private final GitHubAppProperties properties;
    private final ObjectMapper mapper;
    private final HttpClient client;
    @Autowired
    public GitHubAppClient(GitHubAppProperties properties, ObjectMapper mapper) {
        this(properties, mapper, HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10)).proxy(new ProxySelector() {
                    public List<Proxy> select(URI uri) { return List.of(Proxy.NO_PROXY); }
                    public void connectFailed(URI uri, SocketAddress address, java.io.IOException failure) { }
                }).build());
    }
    GitHubAppClient(GitHubAppProperties properties, ObjectMapper mapper, HttpClient client) {
        this.properties = properties; this.mapper = mapper; this.client = client;
    }
    public JsonNode exchange(String code, String verifier) {
        return request(Operation.TOKEN_EXCHANGE, "https://github.com/login/oauth/access_token", "POST", null,
                Map.of("client_id", properties.getClientId(), "client_secret", properties.getClientSecret(),
                        "code", code, "code_verifier", verifier, "redirect_uri", properties.getCallbackUrl()));
    }
    public JsonNode user(String token) {
        return request(Operation.USER_IDENTITY, "https://api.github.com/user", "GET", "Bearer " + token, null);
    }
    public GitHubAppDtos.InstallationPage installations(String token, int page) {
        checkPage(page);
        JsonNode response = api("/user/installations?per_page=100&page=" + page, "GET", token, null);
        List<GitHubAppDtos.Installation> result = new ArrayList<>();
        for (JsonNode node : response.path("installations")) {
            if (allowedInstallation(node)) result.add(new GitHubAppDtos.Installation(node.path("id").asLong(),
                    node.path("account").path("login").asText()));
        }
        return new GitHubAppDtos.InstallationPage(List.copyOf(result), response.path("total_count").asInt() > page * 100);
    }
    public GitHubAppDtos.RepositoryPage repositories(String token, long installation, int page) {
        checkPage(page);
        requireInstallation(installation);
        JsonNode response = api("/user/installations/" + installation + "/repositories?per_page=100&page=" + page, "GET", token, null);
        List<GitHubAppDtos.Repository> result = new ArrayList<>();
        for (JsonNode node : response.path("repositories")) {
            if (!node.path("permissions").path("pull").asBoolean(false) || node.path("disabled").asBoolean()) continue;
            var url = GitHubRepositoryUrl.parse("https://github.com/" + node.path("full_name").asText());
            long id = node.path("id").asLong();
            if (id <= 0) throw GitHubAppException.unavailable();
            result.add(new GitHubAppDtos.Repository(id, installation, url.repository(),
                    url.owner() + "/" + url.repository(), url.canonicalUrl(), node.path("private").asBoolean(true),
                    node.path("default_branch").asText()));
        }
        return new GitHubAppDtos.RepositoryPage(List.copyOf(result), response.path("total_count").asInt() > page * 100);
    }
    public GitHubAppDtos.Repository authorizeRepository(String token, long installation, long repository) {
        if (installation <= 0 || repository <= 0) throw GitHubAppException.denied();
        // The user-token endpoint returns the intersection of explicit user access and installation scope.
        for (int page = 1; page <= 10; page++) {
            var result = repositories(token, installation, page);
            for (var repo : result.repositories()) if (repo.repositoryId() == repository) return repo;
            if (!result.hasNextPage()) throw GitHubAppException.denied();
        }
        throw new GitHubAppException(org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY,
                "설치 범위가 너무 커서 저장소 권한 확인을 완료하지 못했습니다. App에서 선택한 저장소 범위를 줄여 주세요.");
    }
    public String installationToken(long installation, long repository) {
        requireInstallation(installation);
        JsonNode response = api("/app/installations/" + installation + "/access_tokens", "POST", appJwt(),
                Map.of("repository_ids", List.of(repository), "permissions", Map.of("contents", "read", "metadata", "read")));
        String token = response.path("token").asText();
        try {
            Instant expiry = Instant.parse(response.path("expires_at").asText());
            if (token.isBlank() || !expiry.isAfter(Instant.now().plusSeconds(60))
                    || expiry.isAfter(Instant.now().plusSeconds(3700)) || !readOnly(response.path("permissions")))
                throw GitHubAppException.denied();
            JsonNode repos = response.path("repositories");
            if (!repos.isArray() || repos.size() != 1 || repos.get(0).path("id").asLong() != repository)
                throw GitHubAppException.denied();
            return token;
        } catch (RuntimeException failure) {
            if (!token.isBlank()) revokeInstallation(token);
            throw GitHubAppException.denied();
        }
    }
    public void revokeInstallation(String token) {
        try { api("/installation/token", "DELETE", token, null); }
        catch (RuntimeException ignored) { /* The bounded token also expires at GitHub within one hour. */ }
    }
    public boolean revokeUser(String token) {
        try {
            String basic = Base64.getEncoder().encodeToString((properties.getClientId() + ":" + properties.getClientSecret()).getBytes(StandardCharsets.UTF_8));
            request(Operation.TOKEN_REVOCATION, "https://api.github.com/applications/" + properties.getClientId() + "/token", "DELETE", "Basic " + basic, Map.of("access_token", token));
            return true;
        } catch (RuntimeException ignored) { return false; }
    }
    private void requireInstallation(long installation) {
        if (installation <= 0 || !allowedInstallation(api("/app/installations/" + installation, "GET", appJwt(), null)))
            throw GitHubAppException.denied();
    }
    private boolean allowedInstallation(JsonNode node) {
        return node.path("app_id").asLong() == properties.getAppId() && node.path("suspended_at").isNull()
                && readOnly(node.path("permissions"));
    }
    private boolean readOnly(JsonNode permissions) {
        if (!permissions.isObject() || !"read".equals(permissions.path("contents").asText())
                || !"read".equals(permissions.path("metadata").asText())) return false;
        var fields = permissions.fields();
        while (fields.hasNext()) {
            var field = fields.next();
            if (!Set.of("contents", "metadata").contains(field.getKey()) && !"none".equals(field.getValue().asText())) return false;
        }
        return true;
    }
    private void checkPage(int page) {
        if (page < 1 || page > 10) throw new GitHubAppException(org.springframework.http.HttpStatus.BAD_REQUEST, "조회 페이지 범위를 초과했습니다.");
    }
    private JsonNode api(String path, String method, String token, Object body) {
        Operation operation = path.startsWith("/app/") ? Operation.APP_ACCESS
                : path.equals("/installation/token") ? Operation.TOKEN_REVOCATION : Operation.USER_ACCESS;
        return request(operation, "https://api.github.com" + path, method, "Bearer " + token, body);
    }
    private String appJwt() {
        properties.requireConfigured();
        try {
            Path path = Path.of(properties.getPrivateKeyFile());
            if (Files.size(path) > 16384) throw new IllegalArgumentException();
            String pem = Files.readString(path);
            if (!pem.contains("-----BEGIN PRIVATE KEY-----")) throw new IllegalArgumentException();
            byte[] bytes = Base64.getDecoder().decode(pem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", ""));
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
            long now = Instant.now().getEpochSecond();
            String unsigned = encode(mapper.writeValueAsBytes(Map.of("alg", "RS256", "typ", "JWT"))) + "."
                    + encode(mapper.writeValueAsBytes(Map.of("iat", now - 60, "exp", now + 540, "iss", properties.getClientId())));
            Signature signature = Signature.getInstance("SHA256withRSA"); signature.initSign(key);
            signature.update(unsigned.getBytes(StandardCharsets.US_ASCII));
            return unsigned + "." + encode(signature.sign());
        } catch (Exception failure) { throw GitHubAppException.notConfigured(); }
    }
    private String encode(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    private JsonNode request(Operation operation, String url, String method, String authorization, Object body) {
        int status = 0;
        try {
            var builder = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/json").header("User-Agent", "SecureDeploy-read-only")
                    .header("X-GitHub-Api-Version", "2022-11-28");
            if (authorization != null) builder.header("Authorization", authorization);
            if (body != null) builder.header("Content-Type", "application/json");
            builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(body)));
            var pending = client.sendAsync(builder.build(), info -> new LimitedBody());
            HttpResponse<byte[]> response;
            try { response = pending.get(20, TimeUnit.SECONDS); }
            catch (Exception failed) { pending.cancel(true); throw failed; }
            status = response.statusCode();
            if (status < 200 || status >= 300) {
                log.warn("GitHub request stage={} httpStatus={} outcome=HTTP_ERROR", operation, status);
                if (status == 429 || (status == 403 && response.headers().firstValue("X-RateLimit-Remaining").orElse("").equals("0")))
                    throw GitHubAppException.rateLimited();
                if (status == 401) {
                    if (operation == Operation.TOKEN_EXCHANGE || operation == Operation.APP_ACCESS)
                        throw GitHubAppException.appAuthenticationFailed();
                    if (operation == Operation.USER_IDENTITY) throw GitHubAppException.authenticationFailed();
                    throw GitHubAppException.reconnect();
                }
                if (status == 403 || status == 404) {
                    if (operation == Operation.TOKEN_EXCHANGE || operation == Operation.USER_IDENTITY)
                        throw GitHubAppException.authenticationFailed();
                    throw GitHubAppException.denied();
                }
                throw GitHubAppException.unavailable();
            }
            JsonNode result = response.body().length == 0 ? mapper.createObjectNode() : mapper.readTree(response.body());
            if (operation == Operation.TOKEN_EXCHANGE) {
                if (result != null && result.hasNonNull("error")) {
                    OAuthError error = OAuthError.from(result.path("error").asText());
                    // Only allowlisted labels are logged, never GitHub error descriptions or payloads.
                    log.warn("GitHub request stage={} httpStatus={} outcome=OAUTH_ERROR reason={}", operation, status, error);
                    throw error.failure();
                }
                if (result == null || !result.path("access_token").isTextual() || result.path("access_token").asText().isBlank()) {
                    log.warn("GitHub request stage={} httpStatus={} outcome=INVALID_TOKEN_RESPONSE", operation, status);
                    throw GitHubAppException.authenticationFailed();
                }
            }
            log.info("GitHub request stage={} httpStatus={} outcome=SUCCESS", operation, status);
            return result;
        } catch (GitHubAppException failure) { throw failure; }
        catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            log.warn("GitHub request stage={} httpStatus={} outcome=INTERRUPTED", operation, status);
            throw GitHubAppException.unavailable();
        }
        catch (Exception failure) {
            log.warn("GitHub request stage={} httpStatus={} outcome=TRANSPORT_OR_RESPONSE_ERROR", operation, status);
            throw GitHubAppException.unavailable();
        }
    }
    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        private Flow.Subscription subscription;
        public CompletionStage<byte[]> getBody() { return result; }
        public void onSubscribe(Flow.Subscription value) { subscription = value; value.request(1); }
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > 2 * 1024 * 1024 - bytes.size()) {
                    subscription.cancel(); result.completeExceptionally(new IllegalStateException("GitHub response size limit")); return;
                }
                byte[] part = new byte[buffer.remaining()]; buffer.get(part); bytes.writeBytes(part);
            }
            subscription.request(1);
        }
        public void onError(Throwable failure) { result.completeExceptionally(new IllegalStateException("GitHub request failed")); }
        public void onComplete() { result.complete(bytes.toByteArray()); }
    }
}
