package com.securedeploy.upload.service;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.global.util.FileUtils;
import com.securedeploy.project.service.ProjectIgnorePolicy;
import com.securedeploy.upload.model.ExtractedProject;
import com.securedeploy.upload.model.UploadedArchive;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class ZipExtractService {
    private final UploadPolicy policy;

    public ZipExtractService(UploadPolicy policy) { this.policy = policy; }

    public ExtractedProject extract(UploadedArchive archive) {
        ExtractionCount count = new ExtractionCount();
        try {
            count.compressedBytes = Files.size(archive.archivePath());
            if (count.compressedBytes > policy.maxZipBytes()) {
                throw reject("UPLOAD_SIZE", HttpStatus.PAYLOAD_TOO_LARGE, policy.uploadLimitMessage(), count);
            }
            validateSignature(archive.archivePath());
            Path workspace = archive.workspacePath().toRealPath();
            // A fresh private root prevents reuse of links or files from an earlier extraction.
            Path root = Files.createDirectory(workspace.resolve("extracted")).toRealPath();
            extractZip(archive.archivePath(), root, count);
            if (count.entries == 0) throw new IOException("Empty archive");
            Path projectRoot = findProjectRoot(root);
            return new ExtractedProject(resolveProjectName(archive.originalFileName(), projectRoot),
                    archive.workspacePath(), projectRoot, rebase(count.excluded.snapshot(), root.relativize(projectRoot).toString()));
        } catch (IOException | IllegalArgumentException exception) {
            FileUtils.deleteRecursively(archive.workspacePath());
            throw reject("INVALID_ZIP", HttpStatus.BAD_REQUEST,
                    "ZIP 파일이 손상되었거나 안전하게 압축을 해제할 수 없습니다. 프로젝트를 다시 압축해 주세요.", count);
        } catch (RuntimeException exception) {
            FileUtils.deleteRecursively(archive.workspacePath());
            throw exception;
        }
    }

    private void validateSignature(Path zipPath) throws IOException {
        try (var input = Files.newInputStream(zipPath)) {
            byte[] header = input.readNBytes(4);
            if (header.length != 4 || header[0] != 'P' || header[1] != 'K'
                    || header[2] != 3 || header[3] != 4) throw new IOException("Invalid ZIP header");
        }
    }

    private void extractZip(Path zipPath, Path root, ExtractionCount count) throws IOException {
        try (var zip = new ZipInputStream(Files.newInputStream(zipPath))) {
            byte[] buffer = new byte[8192];
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++count.entries > policy.maxEntries()) {
                    throw reject("ENTRY_COUNT", HttpStatus.PAYLOAD_TOO_LARGE,
                            "프로젝트에 파일 또는 폴더가 너무 많습니다. 최대 " + policy.maxEntries()
                                    + "개까지 허용됩니다. " + UploadPolicy.FOLDER_HINT, count);
                }
                Path relative = safeRelativePath(entry.getName(), count);
                Path target = root.resolve(relative).normalize();
                if (!target.startsWith(root) || (target.equals(root) && !entry.isDirectory())) throw unsafePath(count);
                if (entry.getSize() > policy.maxExpandedBytes() - count.expandedBytes) throw expandedLimit(count);

                boolean ignored = ProjectIgnorePolicy.ignores(relative);
                if (ignored && !entry.isDirectory()) count.excluded.record(relative.toString(), "FILE", null, "EXCLUDED", "DIRECTORY_POLICY");
                if (!ignored) {
                    ensureDirectories(root, entry.isDirectory() ? target : target.getParent(), count);
                    if (!entry.isDirectory()) countMaterializedEntry(count);
                }
                // Ignored bytes still consume the budget; closeEntry must not skip unmetered data.
                try (OutputStream output = ignored || entry.isDirectory() ? OutputStream.nullOutputStream()
                        : Files.newOutputStream(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                                LinkOption.NOFOLLOW_LINKS)) {
                    int read;
                    while ((read = zip.read(buffer)) != -1) {
                        count.expandedBytes += read;
                        if (count.expandedBytes > policy.maxExpandedBytes()) throw expandedLimit(count);
                        output.write(buffer, 0, read);
                    }
                }
                zip.closeEntry();
            }
        }
    }

    private Path safeRelativePath(String entryName, ExtractionCount count) {
        String name = entryName.replace('\\', '/');
        if (name.startsWith("/") || name.matches("^[A-Za-z]:.*")) throw unsafePath(count);
        Path path = Path.of(name);
        for (Path segment : path) {
            if (segment.toString().equals("..")) throw unsafePath(count);
        }
        if (path.isAbsolute()) throw unsafePath(count);
        return path;
    }

    private void ensureDirectories(Path root, Path directory, ExtractionCount count) throws IOException {
        Path current = root;
        for (Path part : root.relativize(directory)) {
            current = current.resolve(part);
            if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                countMaterializedEntry(count);
                Files.createDirectory(current);
            }
            if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)
                    || !current.toRealPath().startsWith(root)) throw unsafePath(count);
        }
    }

    private void countMaterializedEntry(ExtractionCount count) {
        // Implicit parent directories also cost filesystem resources, even without ZIP directory entries.
        if (++count.materializedEntries > policy.maxEntries()) {
            throw reject("MATERIALIZED_ENTRY_COUNT", HttpStatus.PAYLOAD_TOO_LARGE,
                    "프로젝트에 파일 또는 폴더가 너무 많습니다. " + UploadPolicy.FOLDER_HINT, count);
        }
    }

    private SecureDeployException unsafePath(ExtractionCount count) {
        return reject("UNSAFE_PATH", HttpStatus.BAD_REQUEST,
                "안전하지 않은 ZIP 경로가 포함되어 있습니다. 프로젝트를 다시 압축해 주세요.", count);
    }

    private SecureDeployException expandedLimit(ExtractionCount count) {
        return reject("EXPANDED_SIZE", HttpStatus.PAYLOAD_TOO_LARGE,
                "압축을 해제한 프로젝트 크기가 허용 범위를 초과했습니다. " + UploadPolicy.FOLDER_HINT, count);
    }

    private SecureDeployException reject(String reason, HttpStatus status, String message, ExtractionCount count) {
        return policy.reject(reason, status, message, count.compressedBytes, count.expandedBytes, count.entries);
    }

    private Path findProjectRoot(Path root) throws IOException {
        try (var children = Files.list(root)) {
            var entries = children.toList();
            // A root manifest beside a source directory must remain inside the scan root.
            return entries.size() == 1 && Files.isDirectory(entries.get(0), LinkOption.NOFOLLOW_LINKS)
                    ? entries.get(0) : root;
        }
    }

    private String resolveProjectName(String originalFileName, Path root) {
        if (!"extracted".equals(root.getFileName().toString())) return root.getFileName().toString();
        return originalFileName == null || originalFileName.isBlank()
                ? "uploaded-project" : originalFileName.replaceFirst("(?i)\\.zip$", "");
    }

    private static final class ExtractionCount {
        final com.securedeploy.project.coverage.CoverageRecorder excluded = new com.securedeploy.project.coverage.CoverageRecorder();
        long compressedBytes;
        long expandedBytes;
        int entries;
        int materializedEntries;
    }

    private com.securedeploy.project.coverage.CoverageLedger rebase(com.securedeploy.project.coverage.CoverageLedger ledger, String prefix) {
        String start = prefix.replace('\\', '/') + "/";
        return new com.securedeploy.project.coverage.CoverageLedger(ledger.schemaVersion(), ledger.policyVersion(), ledger.status(),
                ledger.discoveredFiles(), ledger.selectedFiles(), ledger.unsupportedFiles(), ledger.excludedFiles(), ledger.failedFiles(),
                ledger.inventoryComplete(), ledger.omittedEntries(), ledger.entries().stream().map(e ->
                    new com.securedeploy.project.coverage.CoverageLedger.Entry(e.filePath().startsWith(start)
                        ? e.filePath().substring(start.length()) : e.filePath(), e.kind(), e.fileType(), e.status(), e.reason())).toList(), ledger.analyzers());
    }
}
