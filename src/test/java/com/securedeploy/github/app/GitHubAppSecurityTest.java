package com.securedeploy.github.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.persistence.entity.UserEntity;
import com.securedeploy.persistence.repository.UserRepository;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class GitHubAppSecurityTest {
    GitHubAppProperties properties;
    GitHubConnectionRepository repository;
    UserRepository users;
    GitHubAppClient client;
    GitHubTokenCipher cipher;
    GitHubConnectionService service;
    ObjectMapper json = new ObjectMapper();
    @BeforeEach void setup() {
        properties = properties(); repository = mock(GitHubConnectionRepository.class); users = mock(UserRepository.class);
        client = mock(GitHubAppClient.class); cipher = new GitHubTokenCipher(properties);
        service = new GitHubConnectionService(properties, repository, users, cipher, client);
    }
    static GitHubAppProperties properties() {
        var p = new GitHubAppProperties(); p.setEnabled(true); p.setAppId(123); p.setClientId("fixture-client");
        p.setClientSecret("synthetic-client-not-real"); p.setSlug("fixture-app"); p.setPrivateKeyFile("unused-in-mock");
        byte[] key = new byte[32]; new java.security.SecureRandom().nextBytes(key); p.setEncryptionKey(Base64.getEncoder().encodeToString(key));
        return p;
    }
    @Test void ciphertextIsRandomizedAuthenticatedAndBoundToOwner() {
        String first = cipher.encrypt(1, "synthetic-oauth-token");
        assertThat(first).doesNotContain("synthetic-oauth-token").isNotEqualTo(cipher.encrypt(1, "synthetic-oauth-token"));
        assertThat(cipher.decrypt(1, first)).isEqualTo("synthetic-oauth-token");
        assertThatThrownBy(() -> cipher.decrypt(2, first)).isInstanceOf(GitHubAppException.class);
        assertThatThrownBy(() -> cipher.decrypt(1, first + "tampered")).isInstanceOf(GitHubAppException.class);
    }
    @Test void legacySourceSnapshotWithoutAppFieldsRemainsReadable() {
        var snapshot = new com.securedeploy.github.model.GitHubSourceSnapshotConverter().convertToEntityAttribute(
                "{\"owner\":\"fixture\",\"repository\":\"public\",\"canonicalRepositoryUrl\":\"https://github.com/fixture/public\",\"analyzedBranch\":\"main\",\"commitSha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"shortCommitSha\":\"aaaaaaa\",\"cloneDepth\":1,\"limitations\":[]}");
        assertThat(snapshot.repositoryId()).isNull(); assertThat(snapshot.installationId()).isNull();
        assertThat(snapshot.privateRepository()).isNull(); assertThat(snapshot.analyzedNow().commitSha()).isEqualTo(snapshot.commitSha());
    }
    @Test void stateRejectsDifferentUserSessionAndReplayBeforeExchange() throws Exception {
        String state = query(service.begin(1, "Bearer synthetic-session-a").authorizationUrl(), "state");
        var callback = new GitHubAppDtos.Callback("synthetic-code", state);
        assertThatThrownBy(() -> service.complete(2, "Bearer synthetic-session-a", callback)).isInstanceOf(GitHubAppException.class);
        assertThatThrownBy(() -> service.complete(1, "Bearer synthetic-session-b", callback)).isInstanceOf(GitHubAppException.class);
        verifyNoInteractions(client);
        when(client.exchange(anyString(), anyString())).thenReturn(json.readTree("{\"error\":\"expired_code\"}"));
        assertThatThrownBy(() -> service.complete(1, "Bearer synthetic-session-a", callback)).isInstanceOf(GitHubAppException.class);
        assertThatThrownBy(() -> service.complete(1, "Bearer synthetic-session-a", callback)).isInstanceOf(GitHubAppException.class);
        verify(client, times(1)).exchange(anyString(), anyString());
    }
    @Test void newAttemptAndDisconnectInvalidateOldState() {
        String old = query(service.begin(1, "Bearer synthetic-session").authorizationUrl(), "state");
        service.begin(1, "Bearer synthetic-session");
        assertThatThrownBy(() -> service.complete(1, "Bearer synthetic-session", new GitHubAppDtos.Callback("code", old))).isInstanceOf(GitHubAppException.class);
        String state = query(service.begin(1, "Bearer synthetic-session").authorizationUrl(), "state");
        service.disconnect(1);
        assertThatThrownBy(() -> service.complete(1, "Bearer synthetic-session", new GitHubAppDtos.Callback("code", state))).isInstanceOf(GitHubAppException.class);
        verifyNoInteractions(client);
    }
    @Test void expiredConnectionCannotListRepositoriesOrAuthorizeCollection() {
        var user = mock(UserEntity.class); when(user.getId()).thenReturn(1L);
        var expired = new GitHubConnectionEntity(user, 101, "fixture", cipher.encrypt(1, "synthetic"), Instant.now().minusSeconds(1));
        when(repository.findById(1L)).thenReturn(Optional.of(expired));
        assertThat(service.status(1).reconnectRequired()).isTrue();
        assertThatThrownBy(() -> service.repositories(1, 10, 1)).isInstanceOf(GitHubAppException.class);
        assertThatThrownBy(() -> service.authorize(1, 10, 20)).isInstanceOf(GitHubAppException.class);
        verifyNoInteractions(client);
    }
    @Test void disabledConfigurationDoesNotCallGithub() {
        properties.setEnabled(false);
        assertThat(service.status(1).configured()).isFalse();
        assertThatThrownBy(() -> service.begin(1, "Bearer fixture")).isInstanceOf(GitHubAppException.class);
        verifyNoInteractions(client);
    }
    @Test void expiredStateNeverExchangesCodeAndPkceChallengeMatchesServerVerifier() throws Exception {
        var clock = mock(java.time.Clock.class);
        Instant start = Instant.now(); when(clock.instant()).thenReturn(start);
        service = new GitHubConnectionService(properties, repository, users, cipher, client, clock);
        String url = service.begin(1, "Bearer fixture-session").authorizationUrl();
        String expiredState = query(url, "state");
        when(clock.instant()).thenReturn(start.plusSeconds(301));
        assertThatThrownBy(() -> service.complete(1, "Bearer fixture-session", new GitHubAppDtos.Callback("code", expiredState))).isInstanceOf(GitHubAppException.class);
        verifyNoInteractions(client);
        when(clock.instant()).thenReturn(start);
        url = service.begin(1, "Bearer fixture-session").authorizationUrl();
        String challenge = query(url, "code_challenge");
        when(client.exchange(anyString(), anyString())).thenAnswer(inv -> {
            String verifier = inv.getArgument(1);
            assertThat(Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)))).isEqualTo(challenge);
            return json.readTree("{\"error\":\"synthetic-test-error\"}");
        });
        final String state = query(url, "state");
        assertThatThrownBy(() -> service.complete(1, "Bearer fixture-session", new GitHubAppDtos.Callback("code", state))).isInstanceOf(GitHubAppException.class);
        verify(client).exchange(anyString(), anyString());
    }
    @Test void completedCallbackStoresEncryptedTokenWithSecondsExpiryAndCanBeDecryptedAfterRestart() throws Exception {
        Instant now = Instant.parse("2026-10-16T09:00:00Z");
        service = new GitHubConnectionService(properties, repository, users, cipher, client,
                java.time.Clock.fixed(now, java.time.ZoneOffset.UTC));
        var user = mock(UserEntity.class); when(user.getId()).thenReturn(1L);
        when(users.findById(1L)).thenReturn(Optional.of(user));
        when(client.exchange(anyString(), anyString())).thenReturn(json.readTree(
                "{\"access_token\":\"synthetic-user-token\",\"expires_in\":28800}"));
        when(client.user("synthetic-user-token")).thenReturn(json.readTree("{\"id\":101,\"login\":\"fixture\"}"));
        when(repository.saveAndFlush(any())).thenAnswer(inv -> {
            GitHubConnectionEntity entity = inv.getArgument(0);
            when(repository.findById(1L)).thenReturn(Optional.of(entity));
            return entity;
        });
        String url = service.begin(1, "Bearer synthetic-session").authorizationUrl();
        assertThat(query(url, "redirect_uri")).isEqualTo("http://localhost:5173/");
        var callback = new GitHubAppDtos.Callback("synthetic-code", query(url, "state"));
        assertThat(service.complete(1, "Bearer synthetic-session", callback).connected()).isTrue();
        var saved = repository.findById(1L).orElseThrow();
        assertThat(saved.getExpiresAt()).isEqualTo(now.plusSeconds(28800));
        assertThat(saved.getEncryptedAccessToken()).doesNotContain("synthetic-user-token");
        assertThat(new GitHubTokenCipher(properties).decrypt(1, saved.getEncryptedAccessToken())).isEqualTo("synthetic-user-token");
        assertThatThrownBy(() -> service.complete(1, "Bearer synthetic-session", callback)).isInstanceOf(GitHubAppException.class);
        verify(client, times(1)).exchange(anyString(), anyString());
        verify(client, never()).revokeUser(anyString());
    }
    @Test void failedExchangeDoesNotReachEncryptionPersistenceOrRepositoryListing() {
        when(client.exchange(anyString(), anyString())).thenThrow(GitHubAppException.appAuthenticationFailed());
        String state = query(service.begin(1, "Bearer synthetic-session").authorizationUrl(), "state");
        assertThatThrownBy(() -> service.complete(1, "Bearer synthetic-session", new GitHubAppDtos.Callback("synthetic-code", state)))
                .isInstanceOf(GitHubAppException.class).hasMessageNotContaining("인증이 만료");
        verifyNoInteractions(repository, users);
        verify(client, never()).user(anyString());
        verify(client, never()).revokeUser(anyString());
    }
    @Test void invalidTokenLifetimeIsNotMistakenForExpirationAndMintedTokenIsRevoked() throws Exception {
        for (long lifetime : List.of(0L, -1L, 28800000L)) {
            when(client.exchange(anyString(), anyString())).thenReturn(json.readTree(
                    "{\"access_token\":\"synthetic-user-token\",\"expires_in\":" + lifetime + "}"));
            String state = query(service.begin(1, "Bearer synthetic-session").authorizationUrl(), "state");
            assertThatThrownBy(() -> service.complete(1, "Bearer synthetic-session", new GitHubAppDtos.Callback("synthetic-code", state)))
                    .isInstanceOf(GitHubAppException.class).hasMessageContaining("만료되는 사용자 토큰 설정");
        }
        verifyNoInteractions(repository, users);
        verify(client, never()).user(anyString());
        verify(client, times(3)).revokeUser("synthetic-user-token");
    }
    static String query(String url, String key) {
        return Arrays.stream(URI.create(url).getRawQuery().split("&")).filter(p -> p.startsWith(key + "="))
                .map(p -> java.net.URLDecoder.decode(p.substring(key.length() + 1), StandardCharsets.UTF_8)).findFirst().orElseThrow();
    }
}
