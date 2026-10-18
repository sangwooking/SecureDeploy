package com.securedeploy.analysis.python;

import com.securedeploy.analysis.typescript.ServerAnalysisConverter;
import com.securedeploy.project.model.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;

class PythonServerAnalyzerTest {
    @TempDir Path temp;
    static final String UNSAFE = """
            from django.db import connection
            from rest_framework.decorators import api_view
            @api_view(['GET'])
            def endpoint(request):
                value = request.GET['id']
                with connection.cursor() as cursor:
                    cursor.execute('SELECT * FROM demo WHERE id=' + value)
            """;
    static final String SAFE = UNSAFE.replace("'SELECT * FROM demo WHERE id=' + value", "'SELECT * FROM demo WHERE id=%s', [value]");
    static ProjectStructure project(String content) {
        return new ProjectStructure(Path.of("/unreadable-target"), List.of(new ProjectFile(Path.of("/unreadable-target/views.py"),
                "views.py", ProjectFileType.PYTHON, content.lines().toList())));
    }
    @Test void trustedWorkerProducesValidatedCommonFindingWithoutSourceText() {
        var analyzer = new PythonServerAnalyzer(new PythonAnalysisProperties());
        var result = analyzer.analyze(project(UNSAFE));
        assertThat(result.status()).isEqualTo("COMPLETE");
        assertThat(result.validatedFindings()).hasSize(1);
        var finding = result.validatedFindings().get(0);
        assertThat(finding.sourceType()).isEqualTo("PYTHON_DATA_FLOW");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(finding.evidence().get(0).kind()).isEqualTo("CWE-89");
        assertThat(finding.recommendedAction()).contains("execute(sql, params)");
        String json = new ServerAnalysisConverter().convertToDatabaseColumn(result);
        assertThat(json).doesNotContain("SELECT *", "/unreadable-target");
        assertThat(new ServerAnalysisConverter().convertToEntityAttribute(json)).isEqualTo(result);
        assertThat(analyzer.analyze(project(SAFE)).validatedFindings()).isEmpty();
    }
    @Test void unavailableAndParseFailureNeverBecomeSafe() {
        var config = new PythonAnalysisProperties();
        config.setPythonExecutable(temp.resolve("missing").toString());
        assertThat(new PythonServerAnalyzer(config).analyze(project(UNSAFE)).status()).isEqualTo("UNAVAILABLE");
        config.setEnabled(false);
        assertThat(new PythonServerAnalyzer(config).analyze(project(UNSAFE)).status()).isEqualTo("DISABLED");
        var analyzer = new PythonServerAnalyzer(new PythonAnalysisProperties());
        assertThat(analyzer.analyze(project("def bad(")).files().get(0).parseStatus()).isEqualTo("PARSE_FAILED");
        assertThat(analyzer.analyze(project("x".repeat(100_001))).status()).isEqualTo("PARTIAL");
    }
    @Test void responseWithInventedLocationsOrChildFailuresIsRejected() throws Exception {
        Path dir = Files.createDirectory(temp.resolve("worker"));
        Files.writeString(dir.resolve("worker.py"), "import json,sys\nprint(json.dumps({'schemaVersion':999}))\n");
        var properties = new PythonAnalysisProperties(); properties.setAnalyzerDirectory(dir.toString());
        assertThat(new PythonServerAnalyzer(properties).analyze(project(UNSAFE)).status()).isEqualTo("UNAVAILABLE");
    }
    @Test void parentKillsTimedOutWorker() throws Exception {
        Path dir = Files.createDirectory(temp.resolve("slow"));
        Files.writeString(dir.resolve("worker.py"), "while True: pass\n");
        var properties = new PythonAnalysisProperties(); properties.setAnalyzerDirectory(dir.toString()); properties.setTimeoutSeconds(1);
        assertThat(new PythonServerAnalyzer(properties).analyze(project(UNSAFE)).status()).isEqualTo("TIMEOUT");
    }
    @Test void childEnvironmentIsCleanAndIsolatedFlagsAreActive() throws Exception {
        Path dir = Files.createDirectory(temp.resolve("environment"));
        var expected = new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(project(SAFE));
        String output = new ServerAnalysisConverter().convertToDatabaseColumn(expected);
        Files.writeString(dir.resolve("worker.py"), "import os,sys\nassert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode\n"
                + "assert all(k in ('LANG','LC_CTYPE','__CF_USER_TEXT_ENCODING') for k in os.environ)\n"
                + "sys.stdin.read()\nprint(" + new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(output) + ")\n");
        var properties = new PythonAnalysisProperties(); properties.setAnalyzerDirectory(dir.toString());
        assertThat(new PythonServerAnalyzer(properties).analyze(project(SAFE)).status()).isEqualTo(expected.status());
    }
}
