package com.securedeploy.upload.service;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.project.service.ProjectIgnorePolicy;
import jakarta.annotation.PostConstruct;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.web.servlet.MultipartProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class UploadPolicy {
    private static final Logger log = LoggerFactory.getLogger(UploadPolicy.class);
    public static final String FOLDER_HINT = "node_modules, .git, build, dist, target 등 생성 파일이나 외부 라이브러리 폴더를 제외한 뒤 다시 압축해 주세요.";
    private final MultipartProperties multipart;
    private final FileStorageProperties storage;

    public UploadPolicy(MultipartProperties multipart, FileStorageProperties storage) {
        this.multipart = multipart;
        this.storage = storage;
    }

    @PostConstruct
    void validate() {
        if (maxZipBytes() <= 0 || multipart.getMaxRequestSize().toBytes() <= maxZipBytes()
                || maxExpandedBytes() <= 0 || maxEntries() <= 0
                || storage.getMaxAnalysisFileSize().toBytes() <= 0
                || storage.getMaxAnalysisTotalSize().toBytes() <= 0 || storage.getMaxAnalysisLines() <= 0) {
            throw new IllegalStateException("Upload limits must be positive; multipart request limit must exceed file limit");
        }
    }

    public long maxZipBytes() { return multipart.getMaxFileSize().toBytes(); }
    public long maxExpandedBytes() { return storage.getMaxExpandedSize().toBytes(); }
    public int maxEntries() { return storage.getMaxArchiveEntries(); }
    public String uploadLimitMessage() {
        return "프로젝트 파일은 최대 " + limitLabel() + "까지 업로드할 수 있습니다. " + FOLDER_HINT;
    }

    private String limitLabel() {
        long size = maxZipBytes();
        return size % (1024 * 1024) == 0 ? size / (1024 * 1024) + "MB" : size + "B";
    }

    public PolicyResponse response() {
        return new PolicyResponse(maxZipBytes(), limitLabel(), multipart.getMaxRequestSize().toBytes(),
                maxExpandedBytes(), maxEntries(), ProjectIgnorePolicy.DIRECTORIES, FOLDER_HINT);
    }

    public SecureDeployException reject(String reason, HttpStatus status, String message,
                                        long compressedBytes, long expandedBytes, int entries) {
        log.warn("ZIP rejected reason={} compressedBytes={} expandedBytes={} entries={}",
                reason, compressedBytes, expandedBytes, entries);
        return new SecureDeployException(status, message);
    }

    public record PolicyResponse(long maxZipBytes, String maxZipLabel, long maxRequestBytes,
                                 long maxExpandedBytes, int maxArchiveEntries,
                                 List<String> ignoredDirectories, String folderHint) {}
}
