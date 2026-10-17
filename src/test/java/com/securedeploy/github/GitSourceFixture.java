package com.securedeploy.github;

import com.securedeploy.github.service.GitHubSnapshotFetcher;
import java.nio.file.*;
import java.util.Map;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Constants;

/** Local Git object fixtures only. No remote authentication, scripts, or external network. */
public final class GitSourceFixture {
    public static final Map<String, String> FILES = Map.ofEntries(
        Map.entry("README.md", "Offline monorepo fixture"),
        Map.entry("python/requirements.txt", "-c constraints.txt\nfixture-python\nfixture-range>=2.0\n"),
        Map.entry("python/constraints.txt", "fixture-python==1.0\n"),
        Map.entry("python/server.py", "# Synthetic source, never executed. Python source analysis is unsupported.\n"),
        Map.entry("backend/pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>fixture</groupId><artifactId>backend</artifactId><version>1</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>"),
        Map.entry("backend/module/pom.xml", "<project><dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.10</version></dependency></dependencies></project>"),
        Map.entry("services/build.gradle", "dependencies { implementation 'org.springframework:spring-webmvc:5.3.10' }"),
        Map.entry("services/sub/build.gradle.kts", "dependencies { implementation(\"commons-collections:commons-collections:3.2.1\") }"),
        Map.entry("frontend/package.json", "{\"dependencies\":{\"lodash\":\"4.17.10\"}}"),
        Map.entry("frontend/widget/package.json", "{\"dependencies\":{\"minimist\":\"1.2.0\"}}"),
        Map.entry("frontend/src/App.tsx", "export const App = () => <div dangerouslySetInnerHTML={{__html: location.hash}} />;"),
        Map.entry("backend/src/main/resources/application.properties", "debug=true\nserver.error.include-stacktrace=always\n"),
        Map.entry("backend/src/main/java/AccountController.java", "class AccountController { public String account(String id) { return id; } }"),
        Map.entry("frontend/.env.production", "VITE_API_BASE_URL=http://api.example.invalid"),
        Map.entry("deploy/Dockerfile", "FROM node:latest\n"),
        Map.entry("deploy/k8s/custom.yaml", "kind: Pod\nspec:\n  containers:\n    - name: fixture\n      image: nginx:latest\n"),
        Map.entry("build/ignored.java", "class Ignored {}"),
        Map.entry("node_modules/ignored/package.json", "{\"dependencies\":{\"lodash\":\"1.0.0\"}}")
    );
    public static String create(Path root) throws Exception {
        try (Git git = Git.init().setDirectory(root.toFile()).setInitialBranch("develop").call()) {
            for (var entry : FILES.entrySet()) {
                Path file = root.resolve(entry.getKey()); Files.createDirectories(file.getParent()); Files.writeString(file, entry.getValue());
            }
            return commit(git);
        }
    }
    public static String commit(Git git) throws Exception {
        git.add().addFilepattern(".").call();
        return git.commit().setMessage("Offline fixture").setAuthor("Fixture", "fixture@example.invalid")
                .setCommitter("Fixture", "fixture@example.invalid").call().name();
    }
    public static GitHubSnapshotFetcher fetcher(Path remote) {
        return (url, directory, budget) -> {
            try (Git git = Git.cloneRepository().setURI(remote.toUri().toString()).setBare(true)
                    .setDirectory(directory.toFile()).setCloneSubmodules(false).setNoCheckout(true).call()) {
                var repo = git.getRepository();
                return new GitHubSnapshotFetcher.Revision(repo.getFullBranch().substring(Constants.R_HEADS.length()), repo.resolve(Constants.HEAD).name());
            }
        };
    }
}
