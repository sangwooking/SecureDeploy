package com.securedeploy.editing;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.securedeploy.github.app.*;
import com.securedeploy.github.model.*;
import com.securedeploy.github.service.*;
import com.securedeploy.global.config.FileStorageProperties;
import java.nio.file.*;
import java.util.*;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class EditingSourceServiceTest {
    @TempDir Path temp;
    GitHubConnectionService connections = mock(GitHubConnectionService.class);
    GitHubAppClient client = mock(GitHubAppClient.class);
    GitHubSnapshotFetcher fetcher = mock(GitHubSnapshotFetcher.class);
    EditingSourceService service;
    String sha;
    @BeforeEach void setup() throws Exception {
        var storage = new FileStorageProperties(); storage.setTempDir(temp.toString());
        service = new EditingSourceService(connections, client, fetcher, new GitHubSourceProperties(), storage);
        try (var git = Git.init().setBare(true).setDirectory(temp.resolve("fixture.git").toFile()).call()) { sha = populate(git.getRepository(), FileMode.REGULAR_FILE); }
        when(connections.authorize(1, 2, 3)).thenReturn(new GitHubAppDtos.Repository(3,2,"fixture","fixture/edit","https://github.com/fixture/edit",true,"main"));
        when(client.installationToken(2,3)).thenReturn("synthetic-fixture-only");
        when(fetcher.fetchExact(any(), any(), any(), any(), eq(sha))).thenAnswer(invocation -> {
            Path target = invocation.getArgument(1);
            try (var git = Git.init().setBare(true).setDirectory(target.toFile()).call()) { populate(git.getRepository(), FileMode.REGULAR_FILE); }
            return new GitHubSnapshotFetcher.Revision(null, sha);
        });
    }
    String populate(Repository repository, FileMode mode) throws Exception {
        try (var inserter = repository.newObjectInserter()) {
            var blob = inserter.insert(Constants.OBJ_BLOB, "original\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            var tree = new TreeFormatter(); tree.append("source.ts", mode, blob);
            var commit = new CommitBuilder(); commit.setTreeId(inserter.insert(tree));
            var who = new PersonIdent("fixture", "fixture@example.invalid", new java.util.Date(0), java.util.TimeZone.getTimeZone("UTC"));
            commit.setAuthor(who); commit.setCommitter(who); commit.setMessage("synthetic fixture");
            var id = inserter.insert(commit); inserter.flush(); return id.name();
        }
    }
    GitHubSourceSnapshot source(String commit) { return new GitHubSourceSnapshot("fixture","edit","https://github.com/fixture/edit","main",commit,commit == null ? null : commit.substring(0,7),null,null,null,null,1,0,0,0,List.of()).withAccess(3L,2L,true); }
    void cleaned() throws Exception { try (var entries = Files.list(temp)) { assertTrue(entries.noneMatch(p -> p.getFileName().toString().startsWith("editing-github-"))); } }
    @Test void exactCommitReadOnlyAuthorizationTwiceTokenRevokedAndTempRemoved() throws Exception {
        var entries = service.github(1, source(sha)); assertEquals(1, entries.size());
        assertEquals("source.ts", entries.get(0).path()); verify(connections,times(2)).authorize(1,2,3);
        verify(client).revokeInstallation("synthetic-fixture-only"); verify(fetcher).fetchExact(any(), any(), any(), any(), eq(sha)); cleaned();
    }
    @Test void missingShaAndRevokedPermissionNeverFetch() throws Exception {
        assertThrows(RuntimeException.class, () -> service.github(1, source(null))); verifyNoInteractions(fetcher);
        when(connections.authorize(1,2,3)).thenThrow(GitHubAppException.denied());
        assertThrows(RuntimeException.class, () -> service.github(1, source(sha))); verifyNoInteractions(fetcher); cleaned();
    }
    @Test void failedExactFetchDoesNotFallBackAndStillRevokesAndCleans() throws Exception {
        when(fetcher.fetchExact(any(),any(),any(),any(),eq(sha))).thenThrow(new java.io.IOException("synthetic failure"));
        assertThrows(RuntimeException.class, () -> service.github(1, source(sha)));
        verify(fetcher,never()).fetch(any(),any(),any()); verify(client).revokeInstallation(any()); cleaned();
    }
    @Test void permissionRevokedDuringCollectionDiscardsSources() throws Exception {
        when(connections.authorize(1,2,3)).thenReturn(new GitHubAppDtos.Repository(3,2,"fixture","fixture/edit","https://github.com/fixture/edit",true,"main"))
                .thenThrow(GitHubAppException.denied());
        assertThrows(RuntimeException.class, () -> service.github(1, source(sha))); verify(client).revokeInstallation(any()); cleaned();
    }
}
