package com.securedeploy.github.service;

import com.securedeploy.github.GitSourceFixture;
import com.securedeploy.github.model.GitHubRepositoryUrl;
import java.io.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.GZIPInputStream;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.transport.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class JGitProtocolTest {
    @TempDir Path temp;
    @Test void fullSmartHttpProtocolFetchesDefaultBranchAndShallowCommitOffline() throws Exception {
        Path remote = temp.resolve("remote");
        GitSourceFixture.create(remote);
        try (Git git = Git.open(remote.toFile())) {
            java.nio.file.Files.writeString(remote.resolve("README.md"), "Second offline commit\n");
            String sha = GitSourceFixture.commit(git);
            HttpClient client = mock(HttpClient.class);
            var requests = new ArrayList<HttpRequest>();
            when(client.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<InputStream>>any())).thenAnswer(inv -> {
                HttpRequest request = inv.getArgument(0); requests.add(request);
                var output = new ByteArrayOutputStream();
                boolean advertise = request.uri().getPath().endsWith("/info/refs");
                try (UploadPack pack = new UploadPack(git.getRepository())) {
                    pack.setBiDirectionalPipe(false);
                    pack.setExtraParameters(List.of(request.headers().firstValue("git-protocol").orElse("").split(":")));
                    if (advertise) {
                        var lines = new PacketLineOut(output);
                        lines.writeString("# service=git-upload-pack\n"); lines.end();
                        pack.sendAdvertisedRefs(new RefAdvertiser.PacketLineOutRefAdvertiser(lines));
                    } else {
                        InputStream input = new ByteArrayInputStream(body(request));
                        if (request.headers().firstValue("content-encoding").orElse("").equals("gzip")) input = new GZIPInputStream(input);
                        pack.upload(input, output, null);
                    }
                }
                @SuppressWarnings("unchecked") HttpResponse<InputStream> response = mock(HttpResponse.class);
                when(response.statusCode()).thenReturn(200);
                when(response.headers()).thenReturn(HttpHeaders.of(Map.of("content-type", List.of(advertise
                        ? "application/x-git-upload-pack-advertisement" : "application/x-git-upload-pack-result")), (a,b) -> true));
                when(response.body()).thenReturn(new ByteArrayInputStream(output.toByteArray()));
                return CompletableFuture.completedFuture(response);
            });
            try (var budget = new CloneBudget(new GitHubSourceProperties())) {
                var revision = new JGitSnapshotFetcher(client).fetch(GitHubRepositoryUrl.parse("https://github.com/fixture/protocol"), temp.resolve("clone.git"), budget);
                assertThat(revision.branch()).isEqualTo("develop");
                assertThat(revision.commitSha()).isEqualTo(sha);
            }
            assertThat(requests.size()).isBetween(2, 12);
            try (Git clone = Git.open(temp.resolve("clone.git").toFile())) {
                assertThat(clone.getRepository().getObjectDatabase().getShallowCommits()).hasSize(1);
            }
        }
    }
    private byte[] body(HttpRequest request) throws Exception {
        var complete = new CompletableFuture<byte[]>();
        var bytes = new ByteArrayOutputStream();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<ByteBuffer>() {
            public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer buffer) { byte[] part = new byte[buffer.remaining()]; buffer.get(part); bytes.writeBytes(part); }
            public void onError(Throwable error) { complete.completeExceptionally(error); }
            public void onComplete() { complete.complete(bytes.toByteArray()); }
        });
        return complete.get(1, TimeUnit.SECONDS);
    }
}
