package com.securedeploy.github;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.github.app.*;
import com.securedeploy.github.service.GitHubSnapshotFetcher;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"securedeploy.ai.provider=template", "securedeploy.sca.enabled=false", "securedeploy.threat-intelligence.enabled=false",
        "securedeploy.github.app.enabled=true", "securedeploy.github.app.app-id=123", "securedeploy.github.app.client-id=fixture-client",
        "securedeploy.github.app.client-secret=synthetic-not-real", "securedeploy.github.app.slug=fixture-app",
        "securedeploy.github.app.private-key-file=unused-mocked-client", "securedeploy.github.app.encryption-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
@AutoConfigureMockMvc(print = org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint.NONE)
@Transactional
class PrivateGitHubIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired jakarta.persistence.EntityManager entities;
    @MockBean GitHubAppClient github;
    @MockBean GitHubSnapshotFetcher fetcher;
    @TempDir Path temp;
    String session, sha;
    final List<Path> workspaces = new ArrayList<>();
    final GitHubAppDtos.Repository selected = new GitHubAppDtos.Repository(20, 10, "private", "fixture/private", "https://github.com/fixture/private", true, "develop");

    @BeforeEach void setup() throws Exception {
        Path remote = temp.resolve("remote"); sha = GitSourceFixture.create(remote);
        when(fetcher.fetchAuthenticated(any(), any(), any(), any())).thenAnswer(inv -> {
            Path directory = inv.getArgument(1); workspaces.add(directory.getParent());
            var revision = GitSourceFixture.fetcher(remote).fetch(inv.getArgument(0), directory, inv.getArgument(2));
            assertThat(Files.readString(directory.resolve("config"))).doesNotContain("synthetic-user", "synthetic-install");
            return revision;
        });
        when(github.exchange(anyString(), anyString())).thenReturn(json.readTree("{\"access_token\":\"synthetic-user-token\",\"expires_in\":28800}"));
        when(github.user("synthetic-user-token")).thenReturn(json.readTree("{\"id\":101,\"login\":\"fixture-owner\"}"));
        when(github.authorizeRepository("synthetic-user-token", 10, 20)).thenReturn(selected);
        when(github.repositories("synthetic-user-token", 10, 1)).thenReturn(new GitHubAppDtos.RepositoryPage(List.of(selected), false));
        when(github.installationToken(10, 20)).thenReturn("synthetic-install-token");
        when(github.revokeUser(anyString())).thenReturn(true);
        session = signup();
    }
    @Test void connectsEncryptsCollectsSavesMetadataRescansAndPreservesHistoryAfterDisconnect() throws Exception {
        connect();
        String stored = jdbc.queryForObject("select encrypted_access_token from github_connections", String.class);
        assertThat(stored).doesNotContain("synthetic-user-token");
        assertThat(read("/api/github/connection").toString()).doesNotContain("synthetic-user-token", "encryptedAccessToken");
        assertThat(read("/api/github/installations/10/repositories").at("/repositories/0/repositoryId").asLong()).isEqualTo(20);
        var first = analyze(null);
        long project = first.path("projectId").asLong(), review = first.path("reviewId").asLong();
        assertThat(first.at("/sourceMetadata/commitSha").asText()).isEqualTo(sha);
        assertThat(first.at("/sourceMetadata/privateRepository").asBoolean()).isTrue();
        assertThat(first.at("/sourceMetadata/accessMethod").asText()).isEqualTo("GITHUB_APP");
        assertThat(first.at("/coverage/inspectionScope/assurance").asText()).isEqualTo("NOT_ESTABLISHED");
        assertThat(first.path("vulnerabilityCount").asInt()).isPositive();
        assertThat(first.toString()).doesNotContain("synthetic-user-token", "synthetic-install-token");
        assertThat(read("/api/projects/" + project).path("githubRepositoryId").asLong()).isEqualTo(20);
        var next = analyze(project);
        assertThat(next.path("reviewId")).isNotEqualTo(first.path("reviewId"));
        assertThat(next.at("/comparison/sourceBefore/commitSha").asText()).isEqualTo(sha);
        assertThat(read("/api/workspace").at("/projects/0/latestReview/sourceMetadata/privateRepository").asBoolean()).isTrue();
        assertThat(read("/api/projects/" + project + "/reviews").size()).isEqualTo(2);
        mvc.perform(delete("/api/github/connection").header("Authorization", session)).andExpect(status().isOk());
        entities.flush();
        assertThat(jdbc.queryForObject("select count(*) from github_connections", Integer.class)).isZero();
        mvc.perform(post("/api/projects/" + project + "/reviews/github").header("Authorization", session)
                .contentType(MediaType.APPLICATION_JSON).content("{\"repositoryUrl\":\"https://github.com/fixture/private\"}"))
                .andExpect(status().isConflict());
        assertThat(read("/api/reviews/" + review).path("sourceMetadata")).isEqualTo(first.path("sourceMetadata"));
        assertThat(read("/api/reviews/" + review).path("coverage")).isEqualTo(first.path("coverage"));
        verify(github, times(2)).revokeInstallation("synthetic-install-token");
        verify(fetcher, times(2)).fetchAuthenticated(any(), any(), any(), any());
        verify(fetcher, never()).fetch(any(), any(), any());
        workspaces.forEach(p -> assertThat(p).doesNotExist());
    }
    @Test void anotherUserCannotReadPrivateReviewOrUseOwnersProjectAndInstallation() throws Exception {
        connect(); var result = analyze(null);
        session = signup();
        mvc.perform(get("/api/reviews/" + result.path("reviewId").asLong()).header("Authorization", session)).andExpect(status().isForbidden());
        mvc.perform(post("/api/projects/" + result.path("projectId").asLong() + "/reviews/github/connected")
                .header("Authorization", session).contentType(MediaType.APPLICATION_JSON).content("{\"installationId\":10,\"repositoryId\":20}"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/github/installations/10/repositories").header("Authorization", session)).andExpect(status().isConflict());
        assertThat(read("/api/workspace").path("projectCount").asInt()).isZero();
        verify(fetcher, times(1)).fetchAuthenticated(any(), any(), any(), any());
    }
    @Test void installedButNoUserPermissionStopsBeforeTokenOrSourceAndDoesNotSaveReview() throws Exception {
        connect();
        when(github.authorizeRepository(anyString(), eq(10L), eq(20L))).thenThrow(GitHubAppException.denied());
        int before = jdbc.queryForObject("select count(*) from reviews", Integer.class);
        mvc.perform(post("/api/reviews/github/connected").header("Authorization", session).contentType(MediaType.APPLICATION_JSON)
                .content("{\"installationId\":10,\"repositoryId\":20}")).andExpect(status().isForbidden());
        verify(github, never()).installationToken(anyLong(), anyLong()); verifyNoInteractions(fetcher);
        assertThat(jdbc.queryForObject("select count(*) from reviews", Integer.class)).isEqualTo(before);
    }
    @Test void revokedAccessDuringCollectionCleansSourceAndTokenWithoutSaving() throws Exception {
        connect();
        when(github.authorizeRepository("synthetic-user-token", 10, 20)).thenReturn(selected).thenThrow(GitHubAppException.denied());
        int before = jdbc.queryForObject("select count(*) from reviews", Integer.class);
        mvc.perform(post("/api/reviews/github/connected").header("Authorization", session).contentType(MediaType.APPLICATION_JSON)
                .content("{\"installationId\":10,\"repositoryId\":20}")).andExpect(status().isForbidden());
        verify(github).revokeInstallation("synthetic-install-token"); workspaces.forEach(p -> assertThat(p).doesNotExist());
        assertThat(jdbc.queryForObject("select count(*) from reviews", Integer.class)).isEqualTo(before);
    }
    @Test void callbackRequiresAuthenticationAndNeverAcceptsDifferentLoginSession() throws Exception {
        mvc.perform(post("/api/github/connection/callback").contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"synthetic\",\"state\":\"synthetic\"}")).andExpect(status().isUnauthorized());
        String state = state(); session = signup();
        mvc.perform(post("/api/github/connection/callback").header("Authorization", session).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(Map.of("code", "synthetic-code", "state", state)))).andExpect(status().isBadRequest());
        verify(github, never()).exchange(anyString(), anyString());
    }
    @Test void expiredCredentialsDoNotFetchOrOverwriteReview() throws Exception {
        connect(); var first = analyze(null);
        jdbc.update("update github_connections set expires_at=?", java.sql.Timestamp.from(java.time.Instant.now().minusSeconds(5))); entities.clear();
        mvc.perform(post("/api/reviews/github/connected").header("Authorization", session).contentType(MediaType.APPLICATION_JSON)
                .content("{\"installationId\":10,\"repositoryId\":20}")).andExpect(status().isConflict());
        assertThat(read("/api/reviews/" + first.path("reviewId").asLong()).path("sourceMetadata")).isEqualTo(first.path("sourceMetadata"));
        verify(fetcher, times(1)).fetchAuthenticated(any(), any(), any(), any());
    }
    @Test void explicitAccountSwitchRequiresDisconnectAndKeepsOriginalConnection() throws Exception {
        connect();
        when(github.exchange(anyString(), anyString())).thenReturn(json.readTree("{\"access_token\":\"synthetic-other-account-token\",\"expires_in\":28800}"));
        when(github.user("synthetic-other-account-token")).thenReturn(json.readTree("{\"id\":202,\"login\":\"other-fixture\"}"));
        String state = state();
        mvc.perform(post("/api/github/connection/callback").header("Authorization", session).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(Map.of("code", "synthetic-code", "state", state)))).andExpect(status().isConflict());
        assertThat(read("/api/github/connection").path("login").asText()).isEqualTo("fixture-owner");
        verify(github).revokeUser("synthetic-other-account-token");
    }
    @Test void sameAccountRenewalReplacesCiphertextAndRevokesPreviousToken() throws Exception {
        connect(); String before = jdbc.queryForObject("select encrypted_access_token from github_connections", String.class);
        when(github.exchange(anyString(), anyString())).thenReturn(json.readTree("{\"access_token\":\"synthetic-renewed-user-token\",\"expires_in\":28800}"));
        when(github.user("synthetic-renewed-user-token")).thenReturn(json.readTree("{\"id\":101,\"login\":\"fixture-owner\"}"));
        connect();
        assertThat(jdbc.queryForObject("select encrypted_access_token from github_connections", String.class)).isNotEqualTo(before).doesNotContain("synthetic");
        verify(github).revokeUser("synthetic-user-token");
        assertThat(jdbc.queryForObject("select count(*) from github_connections", Integer.class)).isEqualTo(1);
    }
    @Test void sourceFailureCleansTemporaryObjectsAndRevokesScopedToken() throws Exception {
        connect();
        doAnswer(inv -> {
            Path directory = inv.getArgument(1); workspaces.add(directory.getParent());
            Files.createDirectory(directory); throw new java.io.IOException("synthetic-upstream-error-with-token");
        }).when(fetcher).fetchAuthenticated(any(), any(), any(), any());
        int before = jdbc.queryForObject("select count(*) from reviews", Integer.class);
        String error = mvc.perform(post("/api/reviews/github/connected").header("Authorization", session).contentType(MediaType.APPLICATION_JSON)
                .content("{\"installationId\":10,\"repositoryId\":20}")).andExpect(status().isBadGateway()).andReturn().getResponse().getContentAsString();
        assertThat(error).doesNotContain("synthetic");
        assertThat(jdbc.queryForObject("select count(*) from reviews", Integer.class)).isEqualTo(before);
        verify(github).revokeInstallation("synthetic-install-token"); workspaces.forEach(p -> assertThat(p).doesNotExist());
    }
    String signup() throws Exception {
        return "Bearer " + json.readTree(mvc.perform(post("/api/auth/signup").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(Map.of("email", UUID.randomUUID() + "@private.test.invalid", "password", UUID.randomUUID().toString(), "name", "Offline fixture"))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
    }
    String state() throws Exception {
        var result = json.readTree(mvc.perform(post("/api/github/connection/authorize").header("Authorization", session))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        return Arrays.stream(URI.create(result.path("authorizationUrl").asText()).getRawQuery().split("&"))
                .filter(p -> p.startsWith("state=")).map(p -> p.substring(6)).findFirst().orElseThrow();
    }
    void connect() throws Exception {
        String state = state();
        String result = mvc.perform(post("/api/github/connection/callback").header("Authorization", session).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsBytes(Map.of("code", "synthetic-code", "state", state)))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(result).doesNotContain("synthetic-user-token");
    }
    JsonNode analyze(Long project) throws Exception {
        return json.readTree(mvc.perform(post(project == null ? "/api/reviews/github/connected" : "/api/projects/" + project + "/reviews/github/connected")
                .header("Authorization", session).contentType(MediaType.APPLICATION_JSON).content("{\"installationId\":10,\"repositoryId\":20,\"scanMode\":\"STANDARD\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    JsonNode read(String path) throws Exception { return json.readTree(mvc.perform(get(path).header("Authorization", session)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()); }
}
