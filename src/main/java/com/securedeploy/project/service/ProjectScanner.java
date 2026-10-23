package com.securedeploy.project.service;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.upload.service.UploadPolicy;
import com.securedeploy.project.coverage.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class ProjectScanner {
    private final ProjectFileCollector fileCollector;
    private final FileStorageProperties limits;

    public ProjectScanner(ProjectFileCollector fileCollector, FileStorageProperties limits) {
        this.fileCollector = fileCollector;
        this.limits = limits;
    }

    public ProjectStructure scan(Path projectRoot) {
        return scan(projectRoot, null);
    }

    public ProjectStructure scan(Path projectRoot, CoverageLedger sourceExclusions) {
        List<ProjectFile> files = new ArrayList<>();
        ScanBudget budget = new ScanBudget();
        CoverageRecorder ledger = new CoverageRecorder();
        ledger.merge(sourceExclusions);
        var enumeratedDirectories=new java.util.TreeSet<String>();
        boolean sourceInventoryComplete=sourceExclusions==null||sourceExclusions.inventoryComplete()&&sourceExclusions.omittedEntries()==0;
        try {
            Files.walkFileTree(projectRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (ProjectIgnorePolicy.ignores(projectRoot.relativize(dir))) {
                        ledger.record(projectRoot.relativize(dir).toString(), "DIRECTORY", null, "EXCLUDED", "DIRECTORY_POLICY_SUBTREE_NOT_ENUMERATED");
                        ledger.incomplete();
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) throws IOException {
                    String relative = projectRoot.relativize(path).toString().replace('\\', '/');
                    if (!attrs.isRegularFile() || ProjectIgnorePolicy.ignores(projectRoot.relativize(path))) {
                        ledger.record(relative, "FILE", null, "EXCLUDED", attrs.isSymbolicLink() ? "SYMLINK" : "DIRECTORY_POLICY");
                        return FileVisitResult.CONTINUE;
                    }
                    var type = fileCollector.resolveAnalysisFileType(path);
                    if (type.isPresent()) {
                        List<String> lines;
                        try {
                            if (files.size() >= limits.getMaxArchiveEntries()) throw analysisLimit();
                            lines = readLines(path, budget);
                        } catch (SecureDeployException limit) {
                            ledger.record(relative, "FILE", type.get().name(), "LIMIT_EXCEEDED", "TEXT_BUDGET");
                            ledger.incomplete();
                            throw new CoverageException(limit.getStatus(), limit.getMessage(), ledger.snapshot());
                        } catch (IOException unreadable) {
                            ledger.record(relative, "FILE", type.get().name(), "FAILED", "TEXT_READ_OR_ENCODING");
                            ledger.incomplete();
                            throw new CoverageException(HttpStatus.BAD_REQUEST, "분석 대상 텍스트를 읽지 못해 분석을 중단했습니다. 인코딩과 파일을 확인해 주세요.", ledger.snapshot());
                        }
                        // ZIPs can also contain LFS pointers; a pointer is never actual source code.
                        if (!lines.isEmpty() && lines.get(0).equals("version https://git-lfs.github.com/spec/v1")) {
                            ledger.record(relative, "FILE", type.get().name(), "EXCLUDED", "LFS_POINTER");
                            return FileVisitResult.CONTINUE;
                        }
                        ledger.record(relative, "FILE", type.get().name(), "SELECTED", "PATTERN_ANALYSIS_INPUT");
                        files.add(new ProjectFile(path, projectRoot.relativize(path).toString().replace('\\', '/'), type.get(), lines));
                    } else ledger.record(relative, "FILE", null, "UNSUPPORTED", "NO_SUPPORTED_ANALYZER");
                    return FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult postVisitDirectory(Path dir, IOException failure) {
                    if(failure!=null){ledger.incomplete();throw new CoverageException(HttpStatus.BAD_REQUEST,"디렉터리 목록을 확인하지 못했습니다.",ledger.snapshot());}
                    if(sourceInventoryComplete&&enumeratedDirectories.size()<1001){
                        String relative=projectRoot.relativize(dir).toString().replace('\\','/');
                        enumeratedDirectories.add(relative.isEmpty()?".":relative);
                    }
                    return FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult visitFileFailed(Path path, IOException failure) {
                    ledger.record(projectRoot.relativize(path).toString(), "FILE", null, "FAILED", "FILE_READ");
                    ledger.incomplete();
                    throw new CoverageException(HttpStatus.BAD_REQUEST, "파일을 읽지 못해 분석을 중단했습니다.", ledger.snapshot());
                }
            });
            return new ProjectStructure(projectRoot, files, ledger.snapshot(), enumeratedDirectories.size()>1000?java.util.Set.of():java.util.Set.copyOf(enumeratedDirectories));
        } catch (IOException exception) {
            ledger.incomplete();
            throw new CoverageException(HttpStatus.BAD_REQUEST,
                    "분석 대상 파일을 읽을 수 없습니다. 텍스트 파일의 인코딩과 프로젝트 구성을 확인해 주세요.", ledger.snapshot());
        }
    }

    private List<String> readLines(Path path, ScanBudget budget) throws IOException {
        long available = Math.min(limits.getMaxAnalysisFileSize().toBytes(),
                limits.getMaxAnalysisTotalSize().toBytes() - budget.bytes);
        // Bound both the retained source and a single long/minified line before decoding.
        int maximum = (int) Math.min(available, Integer.MAX_VALUE - 1L);
        if (Files.size(path) > maximum) throw analysisLimit();
        byte[] bytes;
        try (var input = Files.newInputStream(path)) {
            bytes = input.readNBytes(maximum + 1);
        }
        if (bytes.length > maximum) throw analysisLimit();
        budget.bytes += bytes.length;
        String content = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
        List<String> lines = new ArrayList<>();
        var iterator = content.lines().iterator();
        while (iterator.hasNext()) {
            if (++budget.lines > limits.getMaxAnalysisLines()) throw analysisLimit();
            lines.add(iterator.next());
        }
        return lines;
    }

    private SecureDeployException analysisLimit() {
        return new SecureDeployException(HttpStatus.PAYLOAD_TOO_LARGE,
                "분석할 텍스트 파일의 크기 또는 줄 수가 너무 많습니다. " + UploadPolicy.FOLDER_HINT);
    }

    private static final class ScanBudget {
        long bytes;
        int lines;
    }
}
