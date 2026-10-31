package com.securedeploy.github.service;
import com.securedeploy.github.model.*;
import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.source.SourceManifest;
import com.securedeploy.global.error.SecureDeployException;
import java.nio.file.*;
import org.eclipse.jgit.api.Git;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class GitHubExactCommitTest {
 @TempDir Path temp;
 @Test void branchAdvanceAndDeletionNeverReplacePinnedCommitOrItsBytes()throws Exception {
  Path remote=temp.resolve("remote");String first,second;try(var git=Git.init().setDirectory(remote.toFile()).setInitialBranch("main").call()){
   Files.writeString(remote.resolve("app.js"),"export const ready=true;\n");git.add().addFilepattern(".").call();first=git.commit().setMessage("initial").setAuthor("Fixture","fixture@example.invalid").setCommitter("Fixture","fixture@example.invalid").call().name();
   Files.delete(remote.resolve("app.js"));Files.writeString(remote.resolve("other.js"),"changed");git.add().addFilepattern(".").call();git.rm().addFilepattern("app.js").call();second=git.commit().setMessage("moved branch").setAuthor("Fixture","fixture@example.invalid").setCommitter("Fixture","fixture@example.invalid").call().name();}
  var limits=new FileStorageProperties();limits.setTempDir(temp.resolve("work").toString());
  var fetcher=new GitHubSnapshotFetcher(){public Revision fetch(GitHubRepositoryUrl u,Path p,CloneBudget b){throw new AssertionError("HEAD fallback forbidden");}public Revision fetchExact(GitHubRepositoryUrl u,Path p,CloneBudget b,GitHubReadCredential c,String sha)throws Exception{try(var git=Git.cloneRepository().setURI(remote.toUri().toString()).setBare(true).setDirectory(p.toFile()).call()){assertNotNull(git.getRepository().resolve(sha));}return new Revision(null,sha);}};
  var service=new GitHubRepositoryService(limits,new GitHubSourceProperties(),fetcher,new GitTreeExporter(limits,new ProjectFileCollector()));var clone=service.clonePublicRepository("https://github.com/fixture/source",first);assertEquals(first,clone.sourceMetadata().commitSha());assertNotEquals(second,clone.sourceMetadata().commitSha());assertEquals("export const ready=true;\n",Files.readString(clone.repositoryRoot().resolve("app.js")));assertFalse(Files.exists(clone.repositoryRoot().resolve("other.js")));assertEquals(SourceManifest.digest("export const ready=true;\n".getBytes()),SourceManifest.digest(clone.repositoryRoot().resolve("app.js")));
 }
 @Test void wrongCommitIsRejectedBeforeExportAndWithoutHeadFallback()throws Exception{
  var limits=new FileStorageProperties();limits.setTempDir(temp.resolve("work").toString());var fetcher=new GitHubSnapshotFetcher(){public Revision fetch(GitHubRepositoryUrl u,Path p,CloneBudget b){throw new AssertionError();}public Revision fetchExact(GitHubRepositoryUrl u,Path p,CloneBudget b,GitHubReadCredential c,String sha){return new Revision("main","b".repeat(40));}};
  var service=new GitHubRepositoryService(limits,new GitHubSourceProperties(),fetcher,new GitTreeExporter(limits,new ProjectFileCollector()));assertThrows(SecureDeployException.class,()->service.clonePublicRepository("https://github.com/fixture/source","a".repeat(40)));try(var paths=Files.list(temp.resolve("work"))){assertEquals(0,paths.count());}
 }
}
