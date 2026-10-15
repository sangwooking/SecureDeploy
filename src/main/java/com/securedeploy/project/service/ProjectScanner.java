package com.securedeploy.project.service;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.upload.service.UploadPolicy;
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
        List<ProjectFile> files = new ArrayList<>();
        ScanBudget budget = new ScanBudget();
        try {
            Files.walkFileTree(projectRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    return ProjectIgnorePolicy.ignores(projectRoot.relativize(dir))
                            ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) throws IOException {
                    if (!attrs.isRegularFile() || ProjectIgnorePolicy.ignores(projectRoot.relativize(path))) {
                        return FileVisitResult.CONTINUE;
                    }
                    var type = fileCollector.resolveAnalysisFileType(path);
                    if (type.isPresent()) {
                        if (files.size() >= limits.getMaxArchiveEntries()) throw analysisLimit();
                        var lines = readLines(path, budget);
                        // ZIPs can also contain LFS pointers; a pointer is never actual source code.
                        if (!lines.isEmpty() && lines.get(0).equals("version https://git-lfs.github.com/spec/v1")) return FileVisitResult.CONTINUE;
                        files.add(new ProjectFile(path, projectRoot.relativize(path).toString().replace('\\', '/'), type.get(), lines));
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
            return new ProjectStructure(projectRoot, files);
        } catch (IOException exception) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST,
                    "분석 대상 파일을 읽을 수 없습니다. 텍스트 파일의 인코딩과 프로젝트 구성을 확인해 주세요.");
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
