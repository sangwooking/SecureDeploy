package com.securedeploy.upload.service;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.global.util.FileUtils;
import com.securedeploy.upload.model.UploadedArchive;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class UploadService {

    private final FileStorageProperties storageProperties;
    private final UploadPolicy policy;

    public UploadService(FileStorageProperties storageProperties, UploadPolicy policy) {
        this.storageProperties = storageProperties;
        this.policy = policy;
    }

    public UploadedArchive saveZip(MultipartFile file) {
        validateZip(file);

        Path workspacePath = null;
        long copied = 0;
        try {
            Path baseDir = Path.of(storageProperties.getTempDir()).toAbsolutePath().normalize();
            Files.createDirectories(baseDir);
            workspacePath = Files.createTempDirectory(baseDir, "zip-");
            Path archivePath = workspacePath.resolve("upload.zip");
            try (var input = file.getInputStream(); var output = Files.newOutputStream(archivePath)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    copied += read;
                    if (copied > policy.maxZipBytes()) {
                        throw policy.reject("UPLOAD_SIZE", HttpStatus.PAYLOAD_TOO_LARGE,
                                policy.uploadLimitMessage(), copied, 0, 0);
                    }
                    output.write(buffer, 0, read);
                }
            }
            return new UploadedArchive(file.getOriginalFilename(), workspacePath, archivePath);
        } catch (IOException exception) {
            FileUtils.deleteRecursively(workspacePath);
            throw new SecureDeployException(HttpStatus.INTERNAL_SERVER_ERROR, "ZIP 파일 저장 중 오류가 발생했습니다. 다시 시도해 주세요.");
        } catch (RuntimeException exception) {
            FileUtils.deleteRecursively(workspacePath);
            throw exception;
        }
    }

    private void validateZip(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "분석할 ZIP 파일을 선택해 주세요.");
        }

        String originalFileName = file.getOriginalFilename();
        if (originalFileName == null || !originalFileName.toLowerCase(Locale.ROOT).endsWith(".zip")) {
            throw policy.reject("NOT_ZIP", HttpStatus.BAD_REQUEST,
                    "ZIP 형식의 프로젝트 압축 파일만 업로드할 수 있습니다.", file.getSize(), 0, 0);
        }
        if (file.getSize() > policy.maxZipBytes()) {
            throw policy.reject("UPLOAD_SIZE", HttpStatus.PAYLOAD_TOO_LARGE,
                    policy.uploadLimitMessage(), file.getSize(), 0, 0);
        }
    }
}
