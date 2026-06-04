package com.securedeploy.upload.service;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.upload.model.UploadedArchive;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class UploadService {

    private final FileStorageProperties storageProperties;

    public UploadService(FileStorageProperties storageProperties) {
        this.storageProperties = storageProperties;
    }

    public UploadedArchive saveZip(MultipartFile file) {
        validateZip(file);

        try {
            Path baseDir = Path.of(storageProperties.getTempDir()).toAbsolutePath().normalize();
            Path workspacePath = Files.createDirectories(baseDir.resolve(UUID.randomUUID().toString()));
            Path archivePath = workspacePath.resolve("upload.zip");
            file.transferTo(archivePath);
            return new UploadedArchive(file.getOriginalFilename(), workspacePath, archivePath);
        } catch (IOException exception) {
            throw new SecureDeployException(HttpStatus.INTERNAL_SERVER_ERROR, "ZIP 파일 저장 중 오류가 발생했습니다. 다시 시도해 주세요.");
        }
    }

    private void validateZip(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "분석할 ZIP 파일을 선택해 주세요.");
        }

        String originalFileName = file.getOriginalFilename();
        if (originalFileName == null || !originalFileName.toLowerCase(Locale.ROOT).endsWith(".zip")) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "ZIP 형식의 프로젝트 압축 파일만 업로드할 수 있습니다.");
        }
    }
}
