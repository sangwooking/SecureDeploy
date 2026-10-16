package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.FileCoverage;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.stereotype.Service;

@Service
public class TypeScriptServerAnalyzer {
    private static final int MAX_FILES = 100, MAX_FILE_CHARS = 100_000, MAX_TOTAL_CHARS = 1_000_000;
    private static final int MAX_OUTPUT_BYTES = 2_000_000;
    private final Semaphore capacity = new Semaphore(2);
    private final TypeScriptAnalysisProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    public TypeScriptServerAnalyzer(TypeScriptAnalysisProperties properties) { this.properties = properties; }

    public ServerAnalysisSnapshot analyze(ProjectStructure project) {
        var candidates = project.analysisFiles().stream().filter(f -> f.relativePath().matches(".*\\.[jt]sx?$"))
                .sorted(Comparator.comparing(f -> f.relativePath())).toList();
        if (candidates.isEmpty()) return ServerAnalysisSnapshot.unavailable("NOT_APPLICABLE", List.of(), "NO_JAVASCRIPT_OR_TYPESCRIPT_FILES");
        List<Map<String, String>> sources = new ArrayList<>();
        List<FileCoverage> omitted = new ArrayList<>();
        Map<String, Integer> lineCounts = new HashMap<>();
        int total = 0;
        for (var file : candidates) {
            String path = CoverageRecorder.safePath(file.relativePath());
            long length = file.lines().stream().mapToLong(line -> line.length() + 1L).sum();
            if (path.equals("[redacted-path]")) {
                if (omitted.size() < MAX_FILES) omitted.add(skipped(path, "SENSITIVE_PATH_OMITTED"));
            } else if (sources.size() >= MAX_FILES || length > MAX_FILE_CHARS || length + total > MAX_TOTAL_CHARS) {
                if (omitted.size() < MAX_FILES) omitted.add(skipped(path, "SOURCE_LIMIT_EXCEEDED"));
            } else {
                sources.add(Map.of("filePath", path, "content", String.join("\n", file.lines())));
                lineCounts.put(path, file.lines().size()); total += (int) length;
            }
        }
        List<FileCoverage> unavailableFiles = new ArrayList<>(omitted);
        sources.forEach(f -> unavailableFiles.add(new FileCoverage(f.get("filePath"), "NOT_RUN", "NOT_RUN", 0, 0, List.of())));
        if (!properties.isEnabled()) return ServerAnalysisSnapshot.unavailable("DISABLED", unavailableFiles, "ANALYZER_DISABLED");
        if (sources.isEmpty()) return ServerAnalysisSnapshot.unavailable("PARTIAL", unavailableFiles, "NO_SOURCE_WITHIN_LIMITS");
        if (!capacity.tryAcquire()) return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "ANALYZER_CAPACITY_LIMIT");
        Process process = null;
        ExecutorService io = Executors.newFixedThreadPool(2, r -> { var thread = new Thread(r, "typescript-analysis-io"); thread.setDaemon(true); return thread; });
        try {
            Path directory = Path.of(properties.getAnalyzerDirectory()).toRealPath();
            if (!Files.isRegularFile(directory.resolve("worker.mjs"))
                    || !Files.isRegularFile(directory.resolve("node_modules/typescript/lib/typescript.js")))
                return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "TRUSTED_PARSER_NOT_INSTALLED");
            byte[] input = mapper.writeValueAsBytes(Map.of("files", sources));
            var builder = new ProcessBuilder(properties.getNodeExecutable(), "--permission", "--no-addons",
                    "--max-old-space-size=192", "--allow-fs-read=" + directory,
                    directory.resolve("worker.mjs").toString());
            builder.directory(directory.toFile());
            // Do not inherit JWT/DB/GitHub/OpenAI keys, NODE_OPTIONS, preloaders or target module paths.
            builder.environment().clear(); builder.environment().put("LANG", "en_US.UTF-8");
            builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            process = builder.start();
            Process child = process;
            Future<?> writer = io.submit(() -> { try (var output = child.getOutputStream()) { output.write(input); }
                catch (java.io.IOException failure) { throw new IllegalStateException("ANALYZER_INPUT_FAILED"); } });
            Future<byte[]> reader = io.submit(() -> { try (var output = child.getInputStream()) { return output.readNBytes(MAX_OUTPUT_BYTES + 1); } });
            if (!process.waitFor(properties.getTimeoutSeconds(), TimeUnit.SECONDS))
                return ServerAnalysisSnapshot.unavailable("TIMEOUT", unavailableFiles, "ANALYZER_TIMEOUT");
            writer.get(1, TimeUnit.SECONDS);
            byte[] output = reader.get(1, TimeUnit.SECONDS);
            if (process.exitValue() != 0 || output.length > MAX_OUTPUT_BYTES)
                return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "PARSER_PROCESS_FAILED");
            var parsed = mapper.readValue(output, ServerAnalysisSnapshot.class);
            validate(parsed, lineCounts);
            var files = new ArrayList<>(parsed.files()); files.addAll(omitted);
            var limitations = new ArrayList<>(parsed.limitations());
            if (!omitted.isEmpty()) limitations.add("SOURCE_LIMITS_OR_SENSITIVE_PATHS_OMITTED");
            if (candidates.size() > sources.size() + omitted.size()) limitations.add("OMITTED_FILE_DETAILS_TRUNCATED");
            return new ServerAnalysisSnapshot(parsed.schemaVersion(), parsed.analyzerVersion(), parsed.parserVersion(),
                    omitted.isEmpty() ? parsed.status() : "PARTIAL", List.copyOf(files), parsed.findings(), parsed.sqlUses(),
                    parsed.authorizationContexts(), List.copyOf(limitations));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "ANALYSIS_INTERRUPTED");
        } catch (Exception failure) {
            // Never expose source, child stderr or process environment in an API error or log.
            return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "PARSER_PROCESS_OR_RESPONSE_FAILED");
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
                try { process.waitFor(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            io.shutdownNow(); capacity.release();
        }
    }

    private FileCoverage skipped(String path, String reason) {
        return new FileCoverage(path, "LIMIT_EXCEEDED", "NOT_RUN", 0, 0, List.of(reason));
    }

    private void validate(ServerAnalysisSnapshot result, Map<String, Integer> files) {
        if (result.schemaVersion() != 1 || !"ts-server-v1".equals(result.analyzerVersion()) || !"6.0.3".equals(result.parserVersion())
                || result.files().size() != files.size() || result.findings().size() > 200 || result.sqlUses().size() > 200
                || result.authorizationContexts().size() > 200) throw new IllegalArgumentException("INVALID_ANALYZER_RESPONSE");
        if (!result.files().stream().map(FileCoverage::filePath).collect(java.util.stream.Collectors.toSet()).equals(files.keySet()))
            throw new IllegalArgumentException("INVALID_ANALYZER_FILES");
        var locations = new ArrayList<ServerAnalysisSnapshot.Location>();
        result.findings().forEach(f -> { locations.add(f.source()); locations.add(f.sink()); locations.addAll(f.flow()); locations.addAll(f.defenses()); });
        result.sqlUses().forEach(s -> { locations.add(s.location()); locations.addAll(s.trace()); locations.addAll(s.defenses()); });
        result.authorizationContexts().forEach(c -> { locations.add(c.entry()); locations.addAll(c.checks()); locations.addAll(c.defenses()); locations.addAll(c.resources()); });
        for (var location : locations) if (location == null || !files.containsKey(location.filePath()) || location.line() < 1
                || location.line() > files.get(location.filePath())) throw new IllegalArgumentException("INVALID_ANALYZER_LOCATION");
    }
}
