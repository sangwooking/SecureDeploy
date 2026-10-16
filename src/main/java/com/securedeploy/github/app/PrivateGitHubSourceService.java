package com.securedeploy.github.app;

import com.securedeploy.github.model.*;
import com.securedeploy.github.service.*;
import com.securedeploy.global.util.FileUtils;
import org.springframework.stereotype.Service;

@Service
public class PrivateGitHubSourceService {
    private final GitHubConnectionService connections;
    private final GitHubAppClient client;
    private final GitHubRepositoryService sources;
    public PrivateGitHubSourceService(GitHubConnectionService connections, GitHubAppClient client, GitHubRepositoryService sources) {
        this.connections = connections; this.client = client; this.sources = sources;
    }
    public ClonedRepository collect(long userId, long installation, long repository) {
        var selected = connections.authorize(userId, installation, repository);
        String token = client.installationToken(installation, repository);
        ClonedRepository clone = null;
        boolean complete = false;
        try (var credential = new GitHubReadCredential(GitHubRepositoryUrl.parse(selected.repositoryUrl()), token)) {
            clone = sources.cloneAuthorizedRepository(selected.repositoryUrl(), credential);
            var confirmed = connections.authorize(userId, installation, repository);
            if (!selected.repositoryUrl().equals(confirmed.repositoryUrl())) throw GitHubAppException.denied();
            complete = true;
            return new ClonedRepository(clone.repositoryName(), clone.repositoryUrl(), clone.workspacePath(), clone.repositoryRoot(),
                    clone.sourceMetadata().withAccess(repository, installation, confirmed.privateRepository()));
        } finally {
            client.revokeInstallation(token);
            if (!complete && clone != null) FileUtils.deleteRecursively(clone.workspacePath());
        }
    }
}
