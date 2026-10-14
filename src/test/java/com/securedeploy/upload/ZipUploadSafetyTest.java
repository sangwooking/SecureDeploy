package com.securedeploy.upload;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.global.util.FileUtils;
import com.securedeploy.project.service.*;
import com.securedeploy.upload.model.UploadedArchive;
import com.securedeploy.upload.service.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.web.servlet.MultipartProperties;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.util.unit.DataSize;
import org.springframework.web.multipart.MultipartFile;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class ZipUploadSafetyTest {
    @TempDir Path temp;
    FileStorageProperties storage;
    MultipartProperties multipart;
    UploadPolicy policy;
    UploadService upload;
    ZipExtractService extract;

    @BeforeEach void setup() {
        storage = new FileStorageProperties();
        storage.setTempDir(temp.resolve("uploads").toString());
        multipart = new MultipartProperties();
        multipart.setMaxFileSize(DataSize.ofMegabytes(200));
        multipart.setMaxRequestSize(DataSize.ofMegabytes(205));
        policy = new UploadPolicy(multipart, storage);
        upload = new UploadService(storage, policy);
        extract = new ZipExtractService(policy);
    }

    UploadedArchive archive(Map<String, String> entries) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for (var item : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(item.getKey()));
                zip.write(item.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return upload.saveZip(new MockMultipartFile("file", "project.zip", "application/zip", bytes.toByteArray()));
    }

    @Test void publishedLimitsAndNormalZip() throws Exception {
        assertThat(policy.response().maxZipBytes()).isEqualTo(200L * 1024 * 1024);
        assertThat(policy.response().maxRequestBytes()).isEqualTo(205L * 1024 * 1024);
        assertThat(policy.maxExpandedBytes()).isEqualTo(1024L * 1024 * 1024);
        assertThat(policy.maxEntries()).isEqualTo(50_000);
        var result = extract.extract(archive(Map.of("demo/application.properties", "debug=false")));
        assertThat(result.projectName()).isEqualTo("demo");
        assertThat(Files.readString(result.projectRoot().resolve("application.properties"))).isEqualTo("debug=false");
    }

    @Test void actual199MbZipIsStreamedWithoutMultipartByteArray() throws Exception {
        Path source = temp.resolve("large.zip");
        try (var zip = new ZipOutputStream(Files.newOutputStream(source))) {
            zip.setLevel(Deflater.NO_COMPRESSION);
            zip.putNextEntry(new ZipEntry("assets/large.bin"));
            byte[] buffer = new byte[8192];
            for (int i = 0; i < 199 * 1024 * 1024 / buffer.length; i++) zip.write(buffer);
            zip.closeEntry();
        }
        assertThat(Files.size(source)).isBetween(199L * 1024 * 1024, policy.maxZipBytes());
        MultipartFile file = mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("large.zip");
        when(file.getSize()).thenReturn(Files.size(source));
        when(file.getInputStream()).thenAnswer(inv -> Files.newInputStream(source));
        var saved = upload.saveZip(file);
        assertThat(Files.size(saved.archivePath())).isEqualTo(Files.size(source));
        var result = extract.extract(saved);
        assertThat(Files.size(result.projectRoot().resolve("large.bin"))).isEqualTo(199L * 1024 * 1024);
        verify(file, never()).getBytes();
        FileUtils.deleteRecursively(saved.workspacePath());
        assertThat(saved.workspacePath()).doesNotExist();
    }

    @Test void over200MbIsRejectedBeforeReading() throws Exception {
        MultipartFile file = mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("too-large.zip");
        when(file.getSize()).thenReturn(policy.maxZipBytes() + 1);
        assertThatThrownBy(() -> upload.saveZip(file)).isInstanceOfSatisfying(SecureDeployException.class,
                ex -> { assertThat(ex.getStatus()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE); assertThat(ex.getMessage()).contains("200MB"); });
        verify(file, never()).getInputStream();
        assertThat(Path.of(storage.getTempDir())).doesNotExist();
    }

    @Test void streamingLimitCannotBeBypassedByWrongSizeAndCleansPartialUpload() throws Exception {
        multipart.setMaxFileSize(DataSize.ofBytes(20));
        MultipartFile file = mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("wrong-size.zip");
        when(file.getSize()).thenReturn(1L);
        when(file.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[21]));
        assertThatThrownBy(() -> upload.saveZip(file)).isInstanceOfSatisfying(SecureDeployException.class,
                ex -> assertThat(ex.getStatus()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE));
        assertEmptyUploads();
    }

    @Test void uploadIoFailureCleansWorkspace() throws Exception {
        MultipartFile file = mock(MultipartFile.class);
        when(file.getOriginalFilename()).thenReturn("failure.zip");
        when(file.getSize()).thenReturn(1L);
        when(file.getInputStream()).thenThrow(new IOException("Synthetic failure"));
        assertThatThrownBy(() -> upload.saveZip(file)).isInstanceOf(SecureDeployException.class);
        assertEmptyUploads();
    }

    @ParameterizedTest
    @ValueSource(strings = {"src/data.txt", "node_modules/data.txt"})
    void compressedBombStopsDuringReadIncludingIgnoredEntries(String path) throws Exception {
        storage.setMaxExpandedSize(DataSize.ofBytes(1024));
        var saved = archive(Map.of(path, "a".repeat(100_000)));
        assertThat(Files.size(saved.archivePath())).isLessThan(1024);
        assertThatThrownBy(() -> extract.extract(saved)).isInstanceOfSatisfying(SecureDeployException.class,
                ex -> { assertThat(ex.getStatus()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE); assertThat(ex.getMessage()).contains("압축을 해제한 프로젝트"); });
        assertThat(saved.workspacePath()).doesNotExist();
    }

    @Test void cumulativeExpandedLimitAndEntryLimitIncludeDirectories() throws Exception {
        storage.setMaxExpandedSize(DataSize.ofBytes(10));
        assertThatThrownBy(() -> extract.extract(archive(Map.of("a.txt", "123456", "b.txt", "123456"))))
                .isInstanceOf(SecureDeployException.class).hasMessageContaining("크기가 허용 범위");
        storage.setMaxArchiveEntries(2);
        assertThatThrownBy(() -> extract.extract(archive(Map.of("a/", "", "b/", "", "c/", ""))))
                .isInstanceOf(SecureDeployException.class).hasMessageContaining("파일 또는 폴더");
        assertEmptyUploads();
    }

    @Test void boundariesAreInclusive() throws Exception {
        storage.setMaxExpandedSize(DataSize.ofBytes(10));
        storage.setMaxArchiveEntries(2);
        var result = extract.extract(archive(Map.of("a.txt", "12345", "b.txt", "12345")));
        assertThat(Files.readString(result.projectRoot().resolve("a.txt"))).isEqualTo("12345");
    }

    @ParameterizedTest
    @ValueSource(strings = {"../escape.txt", "/absolute.txt", "a/../../escape.txt", "a/../escape.txt",
            "..\\escape.txt", "C:\\escape.txt", "\\\\server\\share.txt", "node_modules/../../escape.txt"})
    void pathEscapesAreRejectedAndCleaned(String path) throws Exception {
        var saved = archive(Map.of(path, "synthetic"));
        assertThatThrownBy(() -> extract.extract(saved)).isInstanceOf(SecureDeployException.class).hasMessageContaining("안전하지 않은 ZIP 경로");
        assertThat(saved.workspacePath()).doesNotExist();
        assertThat(temp.resolve("escape.txt")).doesNotExist();
    }

    @Test void preexistingSymlinkRootCannotBeFollowedOrDeleted() throws Exception {
        Path outside = Files.createDirectory(temp.resolve("outside"));
        Files.writeString(outside.resolve("keep.txt"), "keep");
        var saved = archive(Map.of("application.properties", "debug=true"));
        Files.createSymbolicLink(saved.workspacePath().resolve("extracted"), outside);
        assertThatThrownBy(() -> extract.extract(saved)).isInstanceOf(SecureDeployException.class);
        assertThat(Files.readString(outside.resolve("keep.txt"))).isEqualTo("keep");
        assertThat(outside.resolve("application.properties")).doesNotExist();
        assertThat(saved.workspacePath()).doesNotExist();
    }

    @Test void archiveLinkPayloadIsNeverMaterializedAsFilesystemLink() throws Exception {
        var entries = new LinkedHashMap<String, String>();
        entries.put("link", "../../outside");
        entries.put("link/application.properties", "debug=true");
        assertThatThrownBy(() -> extract.extract(archive(entries))).isInstanceOf(SecureDeployException.class);
        assertEmptyUploads();
    }

    @Test void unixSymlinkAttributesAreNotRestored() throws Exception {
        var saved = archive(Map.of("link", "../../outside"));
        byte[] bytes = Files.readAllBytes(saved.archivePath());
        var binary = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i + 46 <= bytes.length; i++) {
            if (binary.getInt(i) == 0x02014b50) {
                bytes[i + 5] = 3; // UNIX creator
                binary.putInt(i + 38, 0120777 << 16); // symlink external attributes
                break;
            }
        }
        Files.write(saved.archivePath(), bytes);
        var result = extract.extract(saved);
        Path link = result.projectRoot().resolve("link");
        assertThat(Files.isSymbolicLink(link)).isFalse();
        assertThat(Files.readString(link)).isEqualTo("../../outside");
    }

    @Test void implicitDirectoryCountIsBounded() throws Exception {
        storage.setMaxArchiveEntries(3);
        assertThatThrownBy(() -> extract.extract(archive(Map.of("a/b/c/d/file.txt", ""))))
                .isInstanceOf(SecureDeployException.class).hasMessageContaining("파일 또는 폴더");
        assertEmptyUploads();
    }

    @Test void actualFiftyThousandEntryLimitIsEnforcedEvenForIgnoredFiles() throws Exception {
        var entries = new LinkedHashMap<String, String>();
        for (int i = 0; i <= 50_000; i++) entries.put("node_modules/file" + i, "");
        var saved = archive(entries);
        assertThatThrownBy(() -> extract.extract(saved)).isInstanceOf(SecureDeployException.class).hasMessageContaining("50000");
        assertThat(saved.workspacePath()).doesNotExist();
    }

    @Test void generatedDirectoriesAreNotWrittenAndRootManifestsArePreserved() throws Exception {
        var entries = new LinkedHashMap<String, String>();
        for (String dir : ProjectIgnorePolicy.DIRECTORIES) entries.put(dir + "/bad.java", "ignored");
        for (String name : List.of("package.json", "package-lock.json", "pom.xml", "build.gradle", "Dockerfile")) entries.put(name, "manifest");
        entries.put("src/Main.java", "class Main {}");
        var result = extract.extract(archive(entries));
        assertThat(result.projectRoot().getFileName().toString()).isEqualTo("extracted");
        for (String dir : ProjectIgnorePolicy.DIRECTORIES) assertThat(result.projectRoot().resolve(dir)).doesNotExist();
        var structure = new ProjectScanner(new ProjectFileCollector(), storage).scan(result.projectRoot());
        assertThat(structure.analysisFiles()).extracting(f -> f.relativePath())
                .containsExactlyInAnyOrder("package.json", "package-lock.json", "pom.xml", "build.gradle", "Dockerfile", "src/Main.java");
    }

    @Test void nonZipContentAndCrcCorruptionAreRejectedAndCleaned() throws Exception {
        var saved = upload.saveZip(new MockMultipartFile("file", "fake.zip", "application/zip", "not zip".getBytes()));
        assertThatThrownBy(() -> extract.extract(saved)).isInstanceOf(SecureDeployException.class);
        assertThat(saved.workspacePath()).doesNotExist();
        var archive = archive(Map.of("application.properties", "debug=false"));
        byte[] bytes = Files.readAllBytes(archive.archivePath());
        bytes[30 + "application.properties".length()] ^= 127;
        Files.write(archive.archivePath(), bytes);
        assertThatThrownBy(() -> extract.extract(archive)).isInstanceOf(SecureDeployException.class);
        assertEmptyUploads();
    }

    @Test void invalidUtf8EntryNameReturnsBadRequestNotServerError() throws Exception {
        var saved = archive(Map.of("application.properties", "debug=false"));
        byte[] bytes = Files.readAllBytes(saved.archivePath());
        bytes[30] = (byte) 0xff;
        Files.write(saved.archivePath(), bytes);
        assertThatThrownBy(() -> extract.extract(saved)).isInstanceOfSatisfying(SecureDeployException.class,
                ex -> assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        assertEmptyUploads();
    }

    @Test void harmlessDotRootDirectoryIsAccepted() throws Exception {
        var entries = new LinkedHashMap<String, String>();
        entries.put("./", "");
        entries.put("./application.properties", "debug=false");
        var result = extract.extract(archive(entries));
        assertThat(Files.readString(result.projectRoot().resolve("application.properties"))).isEqualTo("debug=false");
    }

    private void assertEmptyUploads() throws IOException {
        try (var paths = Files.list(Path.of(storage.getTempDir()))) { assertThat(paths.toList()).isEmpty(); }
    }
}
