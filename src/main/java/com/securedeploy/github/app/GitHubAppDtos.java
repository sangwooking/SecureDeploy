package com.securedeploy.github.app;

import com.securedeploy.review.model.ScanMode;
import jakarta.validation.constraints.*;
import java.time.Instant;
import java.util.List;

public final class GitHubAppDtos {
    private GitHubAppDtos() { }
    public record ConnectionStatus(boolean configured, boolean connected, boolean reconnectRequired,
            String login, Instant expiresAt, String installationUrl) { }
    public record Authorization(String authorizationUrl) { }
    public record Callback(@NotBlank @Size(max = 512) String code, @NotBlank @Size(max = 100) String state) { }
    public record Installation(long installationId, String account) { }
    public record Repository(long repositoryId, long installationId, String name, String fullName,
            String repositoryUrl, boolean privateRepository, String defaultBranch) { }
    public record RepositoryPage(List<Repository> repositories, boolean hasNextPage) { }
    public record InstallationPage(List<Installation> installations, boolean hasNextPage) { }
    public record Analyze(@Positive long installationId, @Positive long repositoryId, ScanMode scanMode) {
        public Analyze { if (scanMode == null) scanMode = ScanMode.STANDARD; }
    }
}
