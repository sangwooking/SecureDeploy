package com.securedeploy.github.service;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.project.service.ProjectIgnorePolicy;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class GitTreeExporter {
    public record Result(Instant commitTimestamp, int submodules, int lfsPointers, int symlinks, List<String> limitations,
                         com.securedeploy.project.coverage.CoverageLedger sourceExclusions) { }
    private final FileStorageProperties limits;
    private final ProjectFileCollector collector;
    public GitTreeExporter(FileStorageProperties limits, ProjectFileCollector collector) { this.limits = limits; this.collector = collector; }

    public Result export(Path gitDirectory, Path root, String sha, CloneBudget budget) throws IOException {
        long bytes = 0, textBytes = 0;
        int entries = 0, submodules = 0, lfs = 0, symlinks = 0;
        boolean modulesFile = false;
        var excluded = new com.securedeploy.project.coverage.CoverageRecorder();
        try (Repository repository = new FileRepositoryBuilder().setGitDir(gitDirectory.toFile()).setBare().build();
             RevWalk revisions = new RevWalk(repository); TreeWalk tree = new TreeWalk(repository)) {
            var commit = revisions.parseCommit(ObjectId.fromString(sha));
            tree.addTree(commit.getTree());
            while (tree.next()) {
                budget.check();
                if (++entries > limits.getMaxArchiveEntries()) throw limit();
                Path relative = safePath(tree.getPathString());
                FileMode mode = tree.getFileMode(0);
                if (tree.isSubtree()) { tree.enterSubtree(); continue; }
                if (mode.equals(FileMode.GITLINK)) {
                    submodules++;
                    excluded.record(relative.toString(), "DIRECTORY", null, "EXCLUDED", "SUBMODULE_NOT_ENUMERATED");
                    excluded.incomplete();
                    continue;
                }
                if (mode.equals(FileMode.SYMLINK)) {
                    symlinks++; excluded.record(relative.toString(), "FILE", null, "EXCLUDED", "SYMLINK"); continue;
                }
                if (!mode.equals(FileMode.REGULAR_FILE) && !mode.equals(FileMode.EXECUTABLE_FILE)) throw new IOException("Unsupported Git mode");
                ObjectLoader blob = repository.open(tree.getObjectId(0), Constants.OBJ_BLOB);
                if (blob.getSize() > limits.getMaxExpandedSize().toBytes() - bytes) throw limit();
                bytes += blob.getSize();
                if (relative.toString().equals(".gitmodules")) modulesFile = true;
                if (ProjectIgnorePolicy.ignores(relative) || containsGitDirectory(relative)) {
                    excluded.record(relative.toString(), "FILE", null, "EXCLUDED", "DIRECTORY_POLICY"); continue;
                }
                if (blob.getSize() <= 1024 && isLfsPointer(blob.getBytes(1024))) {
                    lfs++; excluded.record(relative.toString(), "FILE", null, "EXCLUDED", "LFS_POINTER"); continue;
                }
                if (collector.resolveAnalysisFileType(relative).isPresent()) {
                    if (blob.getSize() > limits.getMaxAnalysisFileSize().toBytes()
                            || blob.getSize() > limits.getMaxAnalysisTotalSize().toBytes() - textBytes) throw limit();
                    textBytes += blob.getSize();
                }
                Path target = root.resolve(relative).normalize();
                if (!target.startsWith(root) || target.equals(root)) throw new IOException("Unsafe Git path");
                Files.createDirectories(target.getParent());
                try (var input = blob.openStream(); var output = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW, LinkOption.NOFOLLOW_LINKS)) {
                    byte[] buffer = new byte[8192]; int count;
                    while ((count = input.read(buffer)) != -1) { budget.check(); output.write(buffer, 0, count); }
                }
            }
            var notes = new ArrayList<String>();
            if (submodules > 0 || modulesFile) notes.add("Submodule은 이번 분석에 포함되지 않았습니다. 외부 저장소를 자동으로 가져오지 않습니다.");
            if (lfs > 0) notes.add("Git LFS pointer의 실제 파일 내용은 가져오지 않았으며 분석에서 제외했습니다.");
            if (symlinks > 0) notes.add("심볼릭 링크는 따라가지 않으며 분석에서 제외했습니다.");
            return new Result(Instant.ofEpochSecond(commit.getCommitTime()), submodules, lfs, symlinks, List.copyOf(notes), excluded.snapshot());
        }
    }
    static boolean isLfsPointer(byte[] bytes) {
        return new String(bytes, StandardCharsets.US_ASCII).replace("\r\n", "\n").startsWith("version https://git-lfs.github.com/spec/v1\n");
    }
    static Path safePath(String name) throws IOException {
        if (name.contains("\\") || name.startsWith("/") || name.matches("^[A-Za-z]:.*")) throw new IOException("Unsafe Git path");
        for (String segment : name.split("/", -1)) if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) throw new IOException("Unsafe Git path");
        try { return Path.of(name); } catch (InvalidPathException invalid) { throw new IOException("Invalid Git path"); }
    }
    private boolean containsGitDirectory(Path path) {
        for (Path part : path) if (part.toString().equalsIgnoreCase(".git")) return true;
        return false;
    }
    private SecureDeployException limit() {
        return new SecureDeployException(HttpStatus.PAYLOAD_TOO_LARGE,
                "프로젝트가 분석 허용 크기 또는 파일 수를 초과했습니다. 저장소의 대용량 데이터와 빌드 산출물을 확인해 주세요.");
    }
}
