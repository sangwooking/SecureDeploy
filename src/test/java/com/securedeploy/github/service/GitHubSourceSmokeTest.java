package com.securedeploy.github.service;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.util.FileUtils;
import com.securedeploy.project.service.ProjectFileCollector;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;

class GitHubSourceSmokeTest {
    @TempDir Path temp;
    @Test @EnabledIfEnvironmentVariable(named = "GITHUB_SOURCE_SMOKE", matches = "true")
    void anonymousSmallPublicRepositoryReadOnly() {
        var storage = new FileStorageProperties(); storage.setTempDir(temp.toString());
        var service = new GitHubRepositoryService(storage, new GitHubSourceProperties(), new JGitSnapshotFetcher(), new GitTreeExporter(storage, new ProjectFileCollector()));
        var clone = service.clonePublicRepository("https://github.com/octocat/Hello-World");
        try {
            assertThat(clone.sourceMetadata().analyzedBranch()).isNotBlank();
            assertThat(clone.sourceMetadata().commitSha()).matches("[a-f0-9]{40}");
            assertThat(clone.repositoryRoot().resolve("README")).exists();
            assertThat(clone.sourceMetadata().cloneDepth()).isEqualTo(1);
            System.out.println("GitHub anonymous read-only smoke passed; branch=" + clone.sourceMetadata().analyzedBranch()
                    + "; commit=" + clone.sourceMetadata().shortCommitSha() + "; depth=1");
        } finally { FileUtils.deleteRecursively(clone.workspacePath()); }
    }
}
