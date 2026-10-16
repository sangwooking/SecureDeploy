package com.securedeploy.github.service;

import com.securedeploy.github.model.GitHubRepositoryUrl;
import com.securedeploy.global.error.SecureDeployException;
import java.io.*;
import java.net.URL;
import java.net.http.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class PublicGitHubConnectionTest {
    @Test void privateCredentialOnlyReachesExactReadOnlyEndpointAndIsCleared() throws Exception {
        HttpClient client = mock(HttpClient.class);
        var ok = response(200);
        when(client.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<InputStream>>any()))
                .thenReturn(CompletableFuture.completedFuture(ok));
        var repository = GitHubRepositoryUrl.parse("https://github.com/fixture/private");
        try (var budget = new CloneBudget(new GitHubSourceProperties()); var credential = new GitHubReadCredential(repository, "synthetic-private-token")) {
            assertThatThrownBy(() -> new PublicGitHubConnection(new URL("https://attacker.invalid/git-upload-pack"), repository, budget, client, credential)).isInstanceOf(IOException.class);
            assertThatThrownBy(() -> new PublicGitHubConnection(new URL(repository.cloneUrl() + "/git-receive-pack"), repository, budget, client, credential)).isInstanceOf(IOException.class);
            var connection = new PublicGitHubConnection(new URL(repository.cloneUrl() + "/git-upload-pack"), repository, budget, client, credential);
            connection.setRequestProperty("Authorization", "untrusted-header");
            connection.getResponseCode();
            var capture = ArgumentCaptor.forClass(HttpRequest.class); verify(client).sendAsync(capture.capture(), any());
            assertThat(capture.getValue().headers().firstValue("Authorization")).contains("Basic " + Base64.getEncoder().encodeToString("x-access-token:synthetic-private-token".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            assertThat(capture.getValue().uri().toString()).doesNotContain("synthetic-private-token");
            assertThat(credential.toString()).doesNotContain("synthetic-private-token");
            assertThatThrownBy(() -> credential.authorization(GitHubRepositoryUrl.parse("https://github.com/fixture/other"))).isInstanceOf(IllegalStateException.class);
            credential.close(); assertThatThrownBy(() -> credential.authorization(repository)).isInstanceOf(IllegalStateException.class);
        }
    }
    @Test void gitRequestCompressionHeaderIsKeptButCredentialsAreNeverSent() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<InputStream> response = response(200);
        when(client.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<InputStream>>any()))
                .thenReturn(CompletableFuture.completedFuture(response));
        try (var budget = new CloneBudget(new GitHubSourceProperties())) {
            var connection = connection(client, budget);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Encoding", "gzip");
            connection.setRequestProperty("Content-Type", "application/x-git-upload-pack-request");
            for (String name : List.of("Authorization", "Cookie", "Proxy-Authorization", "Host", "X-Api-Key"))
                connection.setRequestProperty(name, "synthetic-do-not-forward");
            connection.getOutputStream().write(new byte[]{31, -117, 8, 0});
            assertThat(connection.getResponseCode()).isEqualTo(200);
            var request = ArgumentCaptor.forClass(HttpRequest.class);
            verify(client, times(1)).sendAsync(request.capture(), any());
            assertThat(request.getValue().headers().firstValue("content-encoding")).contains("gzip");
            assertThat(request.getValue().headers().firstValue("accept-encoding")).contains("identity");
            assertThat(request.getValue().bodyPublisher().orElseThrow().contentLength()).isEqualTo(4);
            assertThat(request.getValue().headers().map().toString()).doesNotContain("synthetic-do-not-forward");
            assertThat(connection.getInputStream().readAllBytes()).isEmpty();
        }
    }
    @Test void redirectIsRejectedWithoutFollowingOrReturningRemoteBody() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<InputStream> response = response(302);
        when(client.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<InputStream>>any()))
                .thenReturn(CompletableFuture.completedFuture(response));
        try (var budget = new CloneBudget(new GitHubSourceProperties())) {
            var connection = connection(client, budget);
            assertThatThrownBy(connection::getResponseCode).isInstanceOf(SecureDeployException.class).hasMessageContaining("최종 공개 저장소 URL");
            verify(client, times(1)).sendAsync(any(), any());
        }
    }
    @Test void connectionTimeoutHasFriendlyTimeoutMessage() throws Exception {
        HttpClient client = mock(HttpClient.class);
        when(client.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<InputStream>>any()))
                .thenReturn(CompletableFuture.failedFuture(new HttpConnectTimeoutException("synthetic")));
        try (var budget = new CloneBudget(new GitHubSourceProperties())) {
            assertThatThrownBy(connection(client, budget)::getResponseCode).isInstanceOf(SecureDeployException.class).hasMessageContaining("너무 오래");
        }
    }
    private PublicGitHubConnection connection(HttpClient client, CloneBudget budget) throws Exception {
        var repository = GitHubRepositoryUrl.parse("https://github.com/fixture/transport");
        return new PublicGitHubConnection(new URL(repository.cloneUrl() + "/git-upload-pack"), repository, budget, client);
    }
    @SuppressWarnings("unchecked") private HttpResponse<InputStream> response(int status) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.headers()).thenReturn(HttpHeaders.of(Map.of("location", List.of("http://127.0.0.1/forbidden")), (k,v) -> true));
        when(response.body()).thenReturn(new ByteArrayInputStream(new byte[0]));
        return response;
    }
}
