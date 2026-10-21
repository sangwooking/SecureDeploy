package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;

class TypeScriptServerAnalyzerTest {
    @TempDir Path temp;
    static final String UNSAFE = "export default { async fetch(request, env) { const id = new URL(request.url).searchParams.get('id'); return env.DB.prepare('SELECT * FROM t WHERE id=' + id).all(); } };";
    static final String SAFE = "export default { async fetch(request, env) { const id = new URL(request.url).searchParams.get('id'); return env.DB.prepare('SELECT * FROM t WHERE id=?').bind(id).all(); } };";
    static ProjectStructure project(String content) {
        return new ProjectStructure(Path.of("/not-readable-target"), List.of(new ProjectFile(Path.of("/not-readable-target/worker.ts"),
                "worker.ts", ProjectFileType.TYPESCRIPT, content.lines().toList())));
    }
    @Test void trustedParserRunsInRestrictedChildAndDoesNotNeedTheTargetFileSystem() {
        var analyzer = new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
        var result = analyzer.analyze(project(UNSAFE));
        assertThat(result.status()).isEqualTo("COMPLETE");
        assertThat(result.parserVersion()).isEqualTo("6.0.3");
        assertThat(result.findings()).hasSize(1);
        assertThat(result.findings().get(0).confidence()).isEqualTo("HIGH");
        assertThat(analyzer.analyze(project(SAFE)).findings()).isEmpty();
        assertThat(analyzer.analyze(project(SAFE)).sqlUses().get(0).kind()).isEqualTo("PARAMETERIZED_QUERY");
    }
    @Test void missingRuntimeAndDisabledAnalyzerNeverClaimNoProblems() {
        var properties = new TypeScriptAnalysisProperties();
        properties.setNodeExecutable(temp.resolve("missing-node").toString());
        var analyzer = new TypeScriptServerAnalyzer(properties);
        assertThat(analyzer.analyze(project(UNSAFE)).status()).isEqualTo("UNAVAILABLE");
        properties.setEnabled(false);
        assertThat(analyzer.analyze(project(UNSAFE)).status()).isEqualTo("DISABLED");
    }
    @Test void timeoutTerminatesOnlyTheAnalysisChild() throws Exception {
        var properties = fixtureWorker("while (true) {};"); properties.setTimeoutSeconds(1);
        assertThat(new TypeScriptServerAnalyzer(properties).analyze(project(UNSAFE)).status()).isEqualTo("TIMEOUT");
    }
    @Test void childDoesNotInheritSecretsAndCannotReadOtherFiles() throws Exception {
        Path outside = Files.writeString(temp.resolve("outside.txt"), "synthetic-only");
        String code = """
                import fs from 'node:fs';
                let blocked = false;
                try { fs.readFileSync(%s); } catch { blocked = true; }
                const envClean = Object.keys(process.env).every(key => ['LANG', '__CF_USER_TEXT_ENCODING'].includes(key));
                let input = ''; for await (const chunk of process.stdin) input += chunk;
                const files = JSON.parse(input).files.map(f => ({filePath:f.filePath, parseStatus:'PARSED',flowStatus:'NOT_SUPPORTED',entrypoints:0,functionsAnalyzed:0,limitations:[]}));
                process.stdout.write(JSON.stringify({schemaVersion:1,analyzerVersion:'ts-server-v15',parserVersion:'6.0.3',status:'PARTIAL',files,findings:[],sqlUses:[],httpUses:[],exposureUses:[],nodeUses:[],authorizationContexts:[],limitations:[blocked && envClean ? 'ISOLATED' : 'ISOLATION_FAILED']}));
                """.formatted(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(outside.toString()));
        var result = new TypeScriptServerAnalyzer(fixtureWorker(code)).analyze(project(UNSAFE));
        assertThat(result.limitations()).contains("ISOLATED").doesNotContain("ISOLATION_FAILED");
    }
    @Test void oversizedFilesAndSensitivePathsAreExplicitlyOmitted() {
        var analyzer = new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
        assertThat(analyzer.analyze(project("x".repeat(100_001))).status()).isEqualTo("PARTIAL");
        var p = new ProjectStructure(temp, List.of(new ProjectFile(temp.resolve("x"),
                "token=synthetic-only.ts", ProjectFileType.TYPESCRIPT, List.of(UNSAFE))));
        assertThat(analyzer.analyze(p).files().get(0).filePath()).isEqualTo("[redacted-path]");
    }
    private TypeScriptAnalysisProperties fixtureWorker(String code) throws Exception {
        Path directory = Files.createDirectory(temp.resolve("analyzer"));
        Files.createDirectories(directory.resolve("node_modules/typescript/lib"));
        Files.writeString(directory.resolve("node_modules/typescript/lib/typescript.js"), "");
        Files.writeString(directory.resolve("worker.mjs"), code);
        var properties = new TypeScriptAnalysisProperties(); properties.setAnalyzerDirectory(directory.toString()); return properties;
    }
}
