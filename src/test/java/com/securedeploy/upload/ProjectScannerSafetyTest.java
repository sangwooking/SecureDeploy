package com.securedeploy.upload;

import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.project.service.*;
import java.nio.file.*;
import java.util.List;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.util.unit.DataSize;
import static org.assertj.core.api.Assertions.*;

class ProjectScannerSafetyTest {
    @TempDir Path temp;
    FileStorageProperties limits = new FileStorageProperties();
    ProjectScanner scanner = new ProjectScanner(new ProjectFileCollector(), limits);

    @Test void ignoresDirectoriesBeforeReadingInvalidUtf8AndNeverFollowsFileSymlinks() throws Exception {
        Path root = Files.createDirectory(temp.resolve("project"));
        for (String dir : ProjectIgnorePolicy.DIRECTORIES) {
            Files.createDirectories(root.resolve("nested/" + dir));
            Files.write(root.resolve("nested/" + dir + "/Bad.java"), new byte[]{(byte) 0xff});
        }
        Path outside = Files.writeString(temp.resolve("outside.java"), "outside");
        Files.createSymbolicLink(root.resolve("Link.java"), outside);
        Files.createSymbolicLink(root.resolve("external"), temp);
        Files.writeString(root.resolve("package.json"), "{}");
        Files.createDirectory(root.resolve("vendor-api"));
        Files.writeString(root.resolve("vendor-api/App.tsx"), "export const App = 1;");
        assertThat(scanner.scan(root).analysisFiles()).extracting(f -> f.relativePath())
                .containsExactlyInAnyOrder("package.json", "vendor-api/App.tsx");
    }

    @Test void sizeBudgetsFailClosedRatherThanSilentlySkippingSources() throws Exception {
        Files.writeString(temp.resolve("App.tsx"), "a".repeat(11));
        limits.setMaxAnalysisFileSize(DataSize.ofBytes(10));
        assertThatThrownBy(() -> scanner.scan(temp)).isInstanceOf(SecureDeployException.class).hasMessageContaining("텍스트 파일");
        limits.setMaxAnalysisFileSize(DataSize.ofBytes(20));
        limits.setMaxAnalysisTotalSize(DataSize.ofBytes(20));
        Files.writeString(temp.resolve("Other.tsx"), "b".repeat(11));
        assertThatThrownBy(() -> scanner.scan(temp)).isInstanceOf(SecureDeployException.class);
    }

    @Test void lineBudgetPreventsManyTinyStringsWhilePreservingCrLf() throws Exception {
        Files.writeString(temp.resolve("App.tsx"), "first\r\nsecond\rthird\n");
        assertThat(scanner.scan(temp).analysisFiles().get(0).lines()).isEqualTo(List.of("first", "second", "third"));
        limits.setMaxAnalysisLines(2);
        assertThatThrownBy(() -> scanner.scan(temp)).isInstanceOf(SecureDeployException.class);
    }
}
