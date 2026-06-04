package com.securedeploy.upload.service;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.upload.model.ExtractedProject;
import com.securedeploy.upload.model.UploadedArchive;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class ZipExtractService {

    public ExtractedProject extract(UploadedArchive archive) {
        Path extractRoot = archive.workspacePath().resolve("extracted").toAbsolutePath().normalize();

        try {
            Files.createDirectories(extractRoot);
            extractZip(archive.archivePath(), extractRoot);
            Path projectRoot = findProjectRoot(extractRoot);
            return new ExtractedProject(resolveProjectName(archive.originalFileName(), projectRoot), archive.workspacePath(), projectRoot);
        } catch (IOException exception) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "ZIP 압축 해제 중 오류가 발생했습니다.");
        }
    }

    private void extractZip(Path zipPath, Path extractRoot) throws IOException {
        try (InputStream inputStream = Files.newInputStream(zipPath);
             ZipInputStream zipInputStream = new ZipInputStream(inputStream)) {

            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                Path targetPath = extractRoot.resolve(entry.getName()).normalize();
                if (!targetPath.startsWith(extractRoot)) {
                    throw new SecureDeployException(HttpStatus.BAD_REQUEST, "안전하지 않은 ZIP 경로가 포함되어 있습니다.");
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(targetPath);
                } else {
                    Path parent = targetPath.getParent();
                    if (parent != null) {
                        Files.createDirectories(parent);
                    }
                    Files.copy(zipInputStream, targetPath);
                }
                zipInputStream.closeEntry();
            }
        }
    }

    private Path findProjectRoot(Path extractRoot) throws IOException {
        try (var children = Files.list(extractRoot)) {
            var directories = children.filter(Files::isDirectory).toList();
            if (directories.size() == 1) {
                return directories.get(0);
            }
            return extractRoot;
        }
    }

    private String resolveProjectName(String originalFileName, Path projectRoot) {
        if (projectRoot.getFileName() != null && !"extracted".equals(projectRoot.getFileName().toString())) {
            return projectRoot.getFileName().toString();
        }
        if (originalFileName == null || originalFileName.isBlank()) {
            return "uploaded-project";
        }
        return originalFileName.replaceFirst("(?i)\\.zip$", "");
    }
}
