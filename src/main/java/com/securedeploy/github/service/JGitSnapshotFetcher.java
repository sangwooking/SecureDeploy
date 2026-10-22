package com.securedeploy.github.service;

import com.securedeploy.github.model.GitHubRepositoryUrl;
import java.io.IOException;
import java.net.*;
import java.nio.file.Path;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.transport.*;
import org.eclipse.jgit.transport.http.*;
import org.springframework.stereotype.Component;

@Component
public class JGitSnapshotFetcher implements GitHubSnapshotFetcher {
    private final java.net.http.HttpClient client;
    public JGitSnapshotFetcher() { this.client = null; }
    JGitSnapshotFetcher(java.net.http.HttpClient client) { this.client = client; }
    public Revision fetch(GitHubRepositoryUrl url, Path gitDirectory, CloneBudget budget) throws Exception {
        return fetch(url, gitDirectory, budget, null);
    }
    public Revision fetchAuthenticated(GitHubRepositoryUrl url, Path gitDirectory, CloneBudget budget,
            GitHubReadCredential credential) throws Exception { return fetch(url, gitDirectory, budget, credential); }
    public Revision fetchExact(GitHubRepositoryUrl url, Path gitDirectory, CloneBudget budget,
            GitHubReadCredential credential, String sha) throws Exception {
        if (sha == null || !sha.matches("[0-9a-f]{40}")) throw new IOException("Exact revision required");
        try (Git git = Git.init().setBare(true).setDirectory(gitDirectory.toFile()).call()) {
            var repository = git.getRepository();
            repository.getConfig().setBoolean("http", null, "followRedirects", false);
            repository.getConfig().setBoolean("http", null, "sslVerify", true);
            git.fetch().setRemote(url.cloneUrl()).setDepth(1).setTagOpt(TagOpt.NO_TAGS)
                    .setRecurseSubmodules(SubmoduleConfig.FetchRecurseSubmodulesMode.NO)
                    .setRefSpecs(new RefSpec(sha + ":refs/editing/source"))
                    .setTimeout(30).setProgressMonitor(budget)
                    .setTransportConfigCallback(transport -> configure(transport, url, budget, credential)).call();
            budget.check();
            // JGit's object-ID fetch does not guarantee a destination ref update.
            // Validate the requested object itself; never resolve HEAD as a fallback.
            try (var revisions = new org.eclipse.jgit.revwalk.RevWalk(repository)) {
                var commit = revisions.parseCommit(ObjectId.fromString(sha));
                if (!commit.name().equals(sha)) throw new IOException("Exact revision unavailable");
            }
            return new Revision(null, sha);
        }
    }
    private Revision fetch(GitHubRepositoryUrl url, Path gitDirectory, CloneBudget budget, GitHubReadCredential credential) throws Exception {
        try (Git git = Git.init().setBare(true).setDirectory(gitDirectory.toFile()).call()) {
            Repository repository = git.getRepository();
            repository.getConfig().setBoolean("http", null, "followRedirects", false);
            repository.getConfig().setBoolean("http", null, "sslVerify", true);
            String branch;
            try (Transport transport = Transport.open(repository, new URIish(url.cloneUrl()))) {
                configure(transport, url, budget, credential);
                try (FetchConnection connection = transport.openFetch()) {
                    Ref head = connection.getRef(Constants.HEAD);
                    if (head == null || !head.isSymbolic() || !head.getTarget().getName().startsWith(Constants.R_HEADS)) {
                        throw new IOException("Default branch unavailable");
                    }
                    branch = head.getTarget().getName();
                    if (!Repository.isValidRefName(branch)) throw new IOException("Invalid default branch");
                }
            }
            // JGit 6.10's extra full-graph check rejects intentionally missing shallow parents.
            // Keep normal pack validation; GitTreeExporter validates the analyzed commit's tree.
            git.fetch().setRemote(url.cloneUrl()).setDepth(1).setTagOpt(TagOpt.NO_TAGS)
                    .setRecurseSubmodules(SubmoduleConfig.FetchRecurseSubmodulesMode.NO)
                    .setRefSpecs(new RefSpec("+" + branch + ":" + branch))
                    .setTimeout(30).setProgressMonitor(budget)
                    .setTransportConfigCallback(transport -> configure(transport, url, budget, credential)).call();
            budget.check();
            ObjectId commit = repository.resolve(branch + "^{commit}");
            if (commit == null) throw new IOException("Commit unavailable");
            return new Revision(branch.substring(Constants.R_HEADS.length()), commit.name());
        }
    }
    private void configure(Transport transport, GitHubRepositoryUrl url, CloneBudget budget, GitHubReadCredential credential) {
        if (!(transport instanceof TransportHttp http) || !transport.getURI().toString().equals(url.cloneUrl())) {
            throw new IllegalArgumentException("Only canonical GitHub HTTPS transport is allowed");
        }
        transport.setCredentialsProvider(new CredentialsProvider() {
            public boolean isInteractive() { return false; }
            public boolean supports(CredentialItem... items) { return false; }
            public boolean get(URIish uri, CredentialItem... items) { return false; }
        });
        transport.setTimeout(30);
        http.setHttpConnectionFactory(new HttpConnectionFactory() {
            public HttpConnection create(URL target) throws IOException {
                return new PublicGitHubConnection(target, url, budget, client, credential);
            }
            public HttpConnection create(URL target, Proxy proxy) throws IOException { return create(target); }
        });
    }
}
