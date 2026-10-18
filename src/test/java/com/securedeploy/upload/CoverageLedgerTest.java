package com.securedeploy.upload;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.project.coverage.*;
import com.securedeploy.project.service.*;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.util.unit.DataSize;
import static org.assertj.core.api.Assertions.*;

class CoverageLedgerTest {
    @TempDir Path temp;
    FileStorageProperties limits = new FileStorageProperties();
    ProjectScanner scanner = new ProjectScanner(new ProjectFileCollector(), limits);
    @Test void inventoryDistinguishesUnsupportedAndPrunedDirectoriesFromPatternInputs() throws Exception {
        Files.writeString(temp.resolve("App.tsx"), "const a=1;");
        Files.writeString(temp.resolve("worker.py"), "placeholder");
        Files.writeString(temp.resolve("worker.go"), "placeholder");
        Files.writeString(temp.resolve("requirements.txt"), "fake==1.0.0");
        Files.createDirectories(temp.resolve("node_modules"));
        Files.writeString(temp.resolve("node_modules/unknown.js"), "ignored");
        var result = scanner.scan(temp).coverage();
        assertThat(result.discoveredFiles()).isEqualTo(4);
        assertThat(result.selectedFiles()).isEqualTo(3);
        assertThat(result.unsupportedFiles()).isEqualTo(1);
        assertThat(result.entries()).anyMatch(e -> e.filePath().equals("requirements.txt") && e.status().equals("SELECTED"));
        assertThat(result.entries()).anyMatch(e -> e.filePath().equals("worker.py") && e.status().equals("SELECTED"));
        assertThat(result.entries()).anyMatch(e -> e.filePath().equals("worker.go") && e.status().equals("UNSUPPORTED"));
        assertThat(result.inventoryComplete()).isFalse();
        assertThat(result.entries()).anyMatch(e -> e.kind().equals("DIRECTORY") && e.reason().contains("NOT_ENUMERATED"));
        assertThat(new CoverageLedgerConverter().convertToDatabaseColumn(result)).doesNotContain(temp.toString(), "placeholder");
    }
    @Test void failureCarriesCoverageWithoutPersistingASuccessOrExposingSourceContent() throws Exception {
        Files.writeString(temp.resolve("App.tsx"), "synthetic-value");
        limits.setMaxAnalysisFileSize(DataSize.ofBytes(2));
        try { scanner.scan(temp); fail("Expected limit"); }
        catch (CoverageException failure) {
            assertThat(failure.coverage().failedFiles()).isEqualTo(1);
            assertThat(failure.coverage().inventoryComplete()).isFalse();
            assertThat(failure.coverage().entries().get(0).status()).isEqualTo("LIMIT_EXCEEDED");
        }
        limits.setMaxAnalysisFileSize(DataSize.ofBytes(100));
        Files.write(temp.resolve("App.tsx"), new byte[]{(byte)0xff});
        try { scanner.scan(temp); fail("Expected encoding failure"); }
        catch (CoverageException failure) {
            assertThat(failure.coverage().entries().get(0).reason()).isEqualTo("TEXT_READ_OR_ENCODING");
        }
    }
    @Test void boundedPathsAndLegacySnapshotsAreExplicit() {
        var recorder = new CoverageRecorder();
        for (int i = 0; i < 2100; i++) recorder.record("file" + i + ".py", "FILE", null, "UNSUPPORTED", "NO_SUPPORTED_ANALYZER");
        assertThat(recorder.snapshot().entries()).hasSize(2000);
        assertThat(recorder.snapshot().discoveredFiles()).isEqualTo(2100);
        assertThat(recorder.snapshot().omittedEntries()).isEqualTo(100);
        assertThat(CoverageRecorder.safePath("../private/secret")).isEqualTo("[redacted-path]");
        assertThat(CoverageRecorder.safePath("/Users/private/file")).isEqualTo("[redacted-path]");
        assertThat(CoverageRecorder.safePath("token=synthetic.js")).isEqualTo("[redacted-path]");
        assertThat(new CoverageLedgerConverter().convertToEntityAttribute(null)).isNull();
    }
}
