package com.securedeploy.upload;

import com.securedeploy.project.coverage.*;
import com.securedeploy.project.model.*;
import com.securedeploy.project.service.*;
import com.securedeploy.global.config.FileStorageProperties;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;

class InspectionScopeTest {
    @TempDir Path root;
    @Test void unsupportedCoreFilesAndUnknownDockerUserRemainVisibleWithoutNewRiskFindings() throws Exception {
        Files.writeString(root.resolve("server.py"), "synthetic source not executed");
        Files.writeString(root.resolve("requirements-production.txt"), "fixture-package==1.0.0");
        Files.writeString(root.resolve("Dockerfile"), "FROM example:1\nCMD [\"app\"]");
        Files.writeString(root.resolve("logo.png"), "not a code area");
        var structure = new ProjectScanner(new ProjectFileCollector(), new FileStorageProperties()).scan(root);
        var scope = InspectionScope.collect(structure.coverage(), structure.analysisFiles());
        assertThat(scope.assurance()).isEqualTo("NOT_ESTABLISHED");
        assertThat(scope.areas()).extracting(InspectionScope.Area::id)
                .containsExactlyInAnyOrder("PYTHON_DEPENDENCIES", "PYTHON_SOURCE", "DOCKER_DEFAULT_STAGE");
        assertThat(scope.areas()).anyMatch(a -> a.id().equals("DOCKER_DEFAULT_STAGE") && a.status().equals("UNKNOWN"));
        String json = new CoverageLedgerConverter().convertToDatabaseColumn(structure.coverage().withInspectionScope(scope));
        assertThat(json).doesNotContain("synthetic source", root.toString(), "fixture-package");
        assertThat(new CoverageLedgerConverter().convertToEntityAttribute(json).inspectionScope()).isEqualTo(scope);
    }
    @Test void legacyScopeIsAbsentAndRecordLimitsNeverBecomeFullEvidence() {
        var recorder = new CoverageRecorder();
        for (int i = 0; i < 2100; i++) recorder.record("src/file" + i + ".py", "FILE", null, "UNSUPPORTED", "NO_SUPPORTED_ANALYZER");
        var ledger = recorder.snapshot();
        var scope = InspectionScope.collect(ledger, List.of());
        assertThat(scope.evidenceComplete()).isFalse();
        assertThat(scope.areas().get(0).observedFiles()).isEqualTo(2000);
        assertThat(scope.areas().get(0).examplePaths()).hasSize(3);
        var converter = new CoverageLedgerConverter();
        String legacy = converter.convertToDatabaseColumn(ledger).replace(",\"inspectionScope\":null", "");
        assertThat(converter.convertToEntityAttribute(legacy).inspectionScope()).isNull();
    }
    @Test void scopeIsMetadataOnlyAndReportsIncompleteAnalyzers() {
        var recorder = new CoverageRecorder();
        recorder.record("../private.py", "FILE", null, "UNSUPPORTED", "NO_SUPPORTED_ANALYZER");
        var ledger = recorder.snapshot().withAnalyzers(List.of(
                new CoverageLedger.Analyzer("SCA", "UNAVAILABLE", "unavailable", Map.of()),
                new CoverageLedger.Analyzer("TYPESCRIPT_SERVER", "PARTIAL", "partial", Map.of())));
        var scope = InspectionScope.collect(ledger, List.of());
        assertThat(scope.incompleteAnalyzers()).containsExactly("SCA:UNAVAILABLE", "TYPESCRIPT_SERVER:PARTIAL");
        assertThat(scope.areas()).isEmpty();
    }
}
