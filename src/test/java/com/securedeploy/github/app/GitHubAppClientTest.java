package com.securedeploy.github.app;

import com.fasterxml.jackson.databind.*;
import java.net.http.*;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpStatus;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(OutputCaptureExtension.class)
class GitHubAppClientTest {
    @TempDir Path temp;
    ObjectMapper json = new ObjectMapper();
    HttpClient http;
    GitHubAppClient client;
    final List<HttpRequest> requests = new ArrayList<>();
    final Map<String, String> replies = new HashMap<>();
    final Map<String, Integer> statuses = new HashMap<>();
    @BeforeEach @SuppressWarnings("unchecked") void setup() throws Exception {
        var properties = GitHubAppSecurityTest.properties();
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var file = temp.resolve("ephemeral-test-key.pem");
        Files.writeString(file, "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----");
        properties.setPrivateKeyFile(file.toString());
        http = mock(HttpClient.class); client = new GitHubAppClient(properties, json, http);
        when(http.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any())).thenAnswer(inv -> {
            HttpRequest request = inv.getArgument(0); requests.add(request);
            String path = request.uri().getPath();
            HttpResponse<byte[]> response = mock(HttpResponse.class);
            when(response.statusCode()).thenReturn(statuses.getOrDefault(path, 200));
            when(response.headers()).thenReturn(HttpHeaders.of(Map.of(), (k, v) -> true));
            when(response.body()).thenReturn(replies.getOrDefault(path, "{}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return CompletableFuture.completedFuture(response);
        });
        replies.put("/app/installations/10", "{\"app_id\":123,\"suspended_at\":null,\"permissions\":{\"contents\":\"read\",\"metadata\":\"read\"}}");
        replies.put("/user/installations/10/repositories", "{\"total_count\":1,\"repositories\":[{\"id\":20,\"full_name\":\"fixture/private\",\"private\":true,\"default_branch\":\"develop\",\"permissions\":{\"pull\":true}}]}");
    }
    @Test void verifiesIntersectionAndRejectsUnlistedOrInaccessibleRepository() {
        var repo = client.authorizeRepository("synthetic-user-token", 10, 20);
        assertThat(repo.repositoryUrl()).isEqualTo("https://github.com/fixture/private");
        assertThat(repo.privateRepository()).isTrue();
        assertThatThrownBy(() -> client.authorizeRepository("synthetic-user-token", 10, 999)).isInstanceOf(GitHubAppException.class);
        replies.put("/user/installations/10/repositories", "{\"total_count\":0,\"repositories\":[]}");
        assertThatThrownBy(() -> client.authorizeRepository("other-user-token", 10, 20)).isInstanceOf(GitHubAppException.class);
        assertThat(requests).allMatch(r -> r.uri().getHost().equals("api.github.com") && !r.uri().toString().contains("token"));
    }
    @Test void suspendedWrongAppAndWritePermissionInstallationsAreRejected() {
        for (String body : List.of(
                "{\"app_id\":456,\"suspended_at\":null,\"permissions\":{\"contents\":\"read\",\"metadata\":\"read\"}}",
                "{\"app_id\":123,\"suspended_at\":\"2026-01-01\",\"permissions\":{\"contents\":\"read\",\"metadata\":\"read\"}}",
                "{\"app_id\":123,\"suspended_at\":null,\"permissions\":{\"contents\":\"write\",\"metadata\":\"read\"}}",
                "{\"app_id\":123,\"suspended_at\":null,\"permissions\":{\"contents\":\"read\",\"metadata\":\"read\",\"issues\":\"write\"}}")) {
            requests.clear(); replies.put("/app/installations/10", body);
            assertThatThrownBy(() -> client.authorizeRepository("synthetic", 10, 20)).isInstanceOf(GitHubAppException.class);
            assertThat(requests).hasSize(1);
        }
    }
    @Test void tokenIsSingleRepositoryReadOnlyAndRevokedOnUnexpectedScope() {
        replies.put("/app/installations/10/access_tokens", "{\"token\":\"synthetic-install-token\",\"expires_at\":\"" + Instant.now().plusSeconds(3500) + "\",\"permissions\":{\"contents\":\"read\",\"metadata\":\"read\"},\"repositories\":[{\"id\":20}]}");
        assertThat(client.installationToken(10, 20)).isEqualTo("synthetic-install-token");
        assertThatThrownBy(() -> client.installationToken(10, 21)).isInstanceOf(GitHubAppException.class);
        assertThat(requests).anyMatch(r -> r.method().equals("DELETE") && r.uri().getPath().equals("/installation/token"));
    }
    @Test void redirectUnauthorizedAndForbiddenNeverExposeResponseContent() {
        for (int status : List.of(302, 401, 403, 404, 500)) {
            statuses.put("/user", status); replies.put("/user", "synthetic-sensitive-upstream-body");
            assertThatThrownBy(() -> client.user("synthetic-token")).isInstanceOf(GitHubAppException.class).hasMessageNotContaining("synthetic");
        }
        assertThat(requests).hasSize(5);
    }
    @Test void maliciousRepositoryUrlAndMissingPullPermissionAreRejected() {
        replies.put("/user/installations/10/repositories", "{\"total_count\":1,\"repositories\":[{\"id\":20,\"full_name\":\"../../localhost\",\"permissions\":{\"pull\":true}}]}");
        assertThatThrownBy(() -> client.authorizeRepository("synthetic", 10, 20)).isInstanceOf(RuntimeException.class);
        replies.put("/user/installations/10/repositories", "{\"total_count\":1,\"repositories\":[{\"id\":20,\"full_name\":\"fixture/private\",\"permissions\":{\"pull\":false}}]}");
        assertThatThrownBy(() -> client.authorizeRepository("synthetic", 10, 20)).isInstanceOf(GitHubAppException.class);
    }
    @Test void oauthErrorsInHttp200AreNotReportedAsExpiredUserTokens(CapturedOutput output) {
        Map<String, HttpStatus> errors = Map.of(
                "incorrect_client_credentials", HttpStatus.SERVICE_UNAVAILABLE,
                "redirect_uri_mismatch", HttpStatus.SERVICE_UNAVAILABLE,
                "bad_verification_code", HttpStatus.BAD_REQUEST,
                "unverified_user_email", HttpStatus.BAD_REQUEST,
                "access_denied", HttpStatus.BAD_REQUEST);
        errors.forEach((error, expected) -> {
            replies.put("/login/oauth/access_token", "{\"error\":\"" + error + "\",\"error_description\":\"synthetic-sensitive-description\"}");
            assertThatThrownBy(() -> client.exchange("synthetic-oauth-code", "synthetic-verifier"))
                    .isInstanceOfSatisfying(GitHubAppException.class, e -> {
                        assertThat(e.getStatus()).isEqualTo(expected);
                        assertThat(e.getMessage()).doesNotContain("인증이 만료", "synthetic");
                    });
        });
        assertThat(output).contains("stage=TOKEN_EXCHANGE httpStatus=200 outcome=OAUTH_ERROR reason=INCORRECT_CLIENT_CREDENTIALS")
                .doesNotContain("synthetic-sensitive-description", "synthetic-oauth-code", "synthetic-verifier", "synthetic-client-not-real");
    }
    @Test void unrecognizedOauthErrorNeverLeaksIntoDiagnostics(CapturedOutput output) {
        replies.put("/login/oauth/access_token", "{\"error\":\"synthetic-sensitive-untrusted-error\"}");
        assertThatThrownBy(() -> client.exchange("synthetic-code", "synthetic-verifier"))
                .isInstanceOfSatisfying(GitHubAppException.class, e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.BAD_GATEWAY));
        assertThat(output).contains("reason=UNKNOWN").doesNotContain("synthetic-sensitive-untrusted-error");
    }
    @Test void missingNullAndMalformedTokensFailBeforeIdentityLookup() {
        for (String body : List.of("{}", "null", "{\"access_token\":null}", "{\"access_token\":12}", "not-json")) {
            replies.put("/login/oauth/access_token", body);
            assertThatThrownBy(() -> client.exchange("synthetic-code", "synthetic-verifier"))
                    .isInstanceOf(GitHubAppException.class).hasMessageNotContaining("인증이 만료");
        }
        assertThat(requests).hasSize(5).allMatch(r -> r.uri().getPath().equals("/login/oauth/access_token"));
    }
    @Test void unauthorizedIsClassifiedByAuthenticationStage() {
        statuses.put("/login/oauth/access_token", 401);
        statuses.put("/user", 401);
        statuses.put("/user/installations", 401);
        statuses.put("/app/installations/10", 401);
        assertThatThrownBy(() -> client.exchange("synthetic-code", "synthetic-verifier"))
                .isInstanceOfSatisfying(GitHubAppException.class, e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        assertThatThrownBy(() -> client.user("synthetic-new-token"))
                .isInstanceOfSatisfying(GitHubAppException.class, e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.BAD_GATEWAY));
        assertThatThrownBy(() -> client.installations("synthetic-stored-token", 1))
                .isInstanceOfSatisfying(GitHubAppException.class, e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.CONFLICT));
        assertThatThrownBy(() -> client.authorizeRepository("synthetic-user-token", 10, 20))
                .isInstanceOfSatisfying(GitHubAppException.class, e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
    }
    @Test void rateLimitAndTransportFailureDoNotImplyRevokedAuthentication() {
        statuses.put("/user", 429);
        assertThatThrownBy(() -> client.user("synthetic-token"))
                .isInstanceOfSatisfying(GitHubAppException.class, e -> assertThat(e.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS));
        doReturn(CompletableFuture.failedFuture(new HttpTimeoutException("synthetic-sensitive-transport-detail")))
                .when(http).sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>any());
        assertThatThrownBy(() -> client.exchange("synthetic-code", "synthetic-verifier"))
                .isInstanceOf(GitHubAppException.class).hasMessageNotContaining("인증이 만료").hasMessageNotContaining("synthetic");
    }
    @Test void successfulExchangeUsesFixedEndpointAndDoesNotLogTokens(CapturedOutput output) {
        replies.put("/login/oauth/access_token", "{\"access_token\":\"synthetic-user-token\",\"expires_in\":28800,\"token_type\":\"bearer\"}");
        assertThat(client.exchange("synthetic-code", "synthetic-verifier").path("expires_in").asLong()).isEqualTo(28800);
        assertThat(requests).hasSize(1);
        assertThat(requests.get(0).uri().toString()).isEqualTo("https://github.com/login/oauth/access_token");
        assertThat(requests.get(0).headers().firstValue("Authorization")).isEmpty();
        assertThat(output).contains("stage=TOKEN_EXCHANGE httpStatus=200 outcome=SUCCESS").doesNotContain("synthetic-user-token");
    }
}
