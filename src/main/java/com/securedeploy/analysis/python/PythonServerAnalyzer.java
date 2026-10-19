package com.securedeploy.analysis.python;

import com.securedeploy.analysis.typescript.ServerAnalysisSnapshot;
import com.securedeploy.analysis.typescript.ServerFlowFinding;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.FileCoverage;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.stereotype.Service;

@Service
public class PythonServerAnalyzer {
    private static final int MAX_FILES = 100, MAX_FILE_CHARS = 100_000, MAX_TOTAL_CHARS = 1_000_000;
    private static final int MAX_OUTPUT_BYTES = 2_000_000;
    private final Semaphore capacity = new Semaphore(2);
    private final PythonAnalysisProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    public PythonServerAnalyzer(PythonAnalysisProperties properties) { this.properties = properties; }

    public ServerAnalysisSnapshot analyze(ProjectStructure project) {
        var candidates = PythonSourceSelector.order(project.analysisFiles().stream()
                .filter(f -> f.type() == com.securedeploy.project.model.ProjectFileType.PYTHON).toList());
        if (candidates.isEmpty()) return unavailable("NOT_APPLICABLE", List.of(), "NO_PYTHON_FILES");
        List<Map<String, String>> sources = new ArrayList<>();
        List<FileCoverage> omitted = new ArrayList<>();
        Map<String, Integer> lineCounts = new HashMap<>();
        Map<String, String> selectionReasons = new HashMap<>();
        Map<String, Integer> omissionReasons = new TreeMap<>();
        int total = 0;
        for (var candidate : candidates) {
            var file = candidate.file();
            String path = CoverageRecorder.safePath(file.relativePath());
            long length = file.lines().stream().mapToLong(line -> line.length() + 1L).sum();
            if (path.equals("[redacted-path]")) {
                omissionReasons.merge("SENSITIVE_PATH_OMITTED", 1, Integer::sum);
                if (omitted.size() < MAX_FILES) omitted.add(skipped(path, "SENSITIVE_PATH_OMITTED"));
            } else if (sources.size() >= MAX_FILES || length > MAX_FILE_CHARS || length + total > MAX_TOTAL_CHARS) {
                String reason = length > MAX_FILE_CHARS ? "FILE_CHARACTER_LIMIT"
                        : sources.size() >= MAX_FILES ? "FILE_COUNT_LIMIT" : "TOTAL_CHARACTER_LIMIT";
                omissionReasons.merge(reason, 1, Integer::sum);
                if (omitted.size() < MAX_FILES) omitted.add(skipped(path, reason).withSelectionReason(candidate.reason()));
            } else {
                sources.add(Map.of("filePath", path, "content", String.join("\n", file.lines())));
                lineCounts.put(path, file.lines().size()); total += (int) length;
                selectionReasons.put(path, candidate.reason());
            }
        }
        List<FileCoverage> unavailableFiles = new ArrayList<>(omitted);
        sources.forEach(f -> unavailableFiles.add(new FileCoverage(f.get("filePath"), "NOT_RUN", "NOT_RUN", 0, 0, List.of())));
        var selection = new ServerAnalysisSnapshot.SelectionCoverage(candidates.size(), sources.size(),
                candidates.size() - sources.size(), candidates.size() - sources.size() - omitted.size(), total, Map.copyOf(omissionReasons));
        if (!properties.isEnabled()) return unavailable("DISABLED", unavailableFiles, "ANALYZER_DISABLED").withSelectionCoverage(selection);
        if (sources.isEmpty()) return unavailable("PARTIAL", unavailableFiles, "NO_SOURCE_WITHIN_LIMITS").withSelectionCoverage(selection);
        if (!capacity.tryAcquire()) return unavailable("UNAVAILABLE", unavailableFiles, "ANALYZER_CAPACITY_LIMIT").withSelectionCoverage(selection);
        Process process = null;
        ExecutorService io = Executors.newFixedThreadPool(2, r -> { var thread = new Thread(r, "python-analysis-io"); thread.setDaemon(true); return thread; });
        try {
            Path directory = Path.of(properties.getAnalyzerDirectory()).toRealPath();
            if (!Files.isRegularFile(directory.resolve("worker.py")))
                return unavailable("UNAVAILABLE", unavailableFiles, "TRUSTED_PARSER_NOT_INSTALLED").withSelectionCoverage(selection);
            byte[] input = mapper.writeValueAsBytes(Map.of("files", sources));
            var builder = new ProcessBuilder(properties.getPythonExecutable(), "-I", "-S", "-B",
                    directory.resolve("worker.py").toString());
            builder.directory(directory.toFile());
            // Do not inherit JWT/DB/GitHub/OpenAI keys, PYTHONPATH, site hooks or target module paths.
            builder.environment().clear(); builder.environment().put("LANG", "en_US.UTF-8");
            builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            process = builder.start();
            Process child = process;
            Future<?> writer = io.submit(() -> { try (var output = child.getOutputStream()) { output.write(input); }
                catch (java.io.IOException failure) { throw new IllegalStateException("ANALYZER_INPUT_FAILED"); } });
            Future<byte[]> reader = io.submit(() -> { try (var output = child.getInputStream()) { return output.readNBytes(MAX_OUTPUT_BYTES + 1); } });
            if (!process.waitFor(properties.getTimeoutSeconds(), TimeUnit.SECONDS))
                return unavailable("TIMEOUT", unavailableFiles, "ANALYZER_TIMEOUT").withSelectionCoverage(selection);
            writer.get(1, TimeUnit.SECONDS);
            byte[] output = reader.get(1, TimeUnit.SECONDS);
            if (process.exitValue() != 0 || output.length > MAX_OUTPUT_BYTES)
                return unavailable("UNAVAILABLE", unavailableFiles, "PARSER_PROCESS_FAILED").withSelectionCoverage(selection);
            var parsed = mapper.readValue(output, ServerAnalysisSnapshot.class);
            validate(parsed, lineCounts);
            var files = new ArrayList<>(parsed.files().stream()
                    .map(f -> f.withSelectionReason(selectionReasons.get(f.filePath()))).toList()); files.addAll(omitted);
            var limitations = new ArrayList<>(parsed.limitations());
            if (!omitted.isEmpty()) limitations.add("SOURCE_LIMITS_OR_SENSITIVE_PATHS_OMITTED");
            limitations.add("LEXICAL_SELECTION_HINTS_NOT_VERIFIED_ENTRIES");
            if (candidates.stream().anyMatch(c -> c.reason().equals("SELECTION_HINT_LIMIT"))) limitations.add("SELECTION_HINT_LIMIT");
            if (candidates.size() > sources.size() + omitted.size()) limitations.add("OMITTED_FILE_DETAILS_TRUNCATED");
            var deployment = parsed.deploymentAnalysis();
            if (deployment != null && !omitted.isEmpty()) {
                var configFiles = new ArrayList<>(deployment.files());
                omitted.forEach(f -> configFiles.add(new com.securedeploy.analysis.deployment.DeploymentSnapshot.FileResult(
                        f.filePath(), "PYTHON_SETTINGS_CANDIDATE", "LIMIT_EXCEEDED", List.of(), List.of("SETTINGS_ROLE_NOT_INSPECTED"))));
                deployment = new com.securedeploy.analysis.deployment.DeploymentSnapshot(1, "deployment-v1", "PARTIAL", configFiles,
                        List.of(), List.of("SOURCE_LIMITS_OR_SENSITIVE_PATHS_OMITTED"));
            }
            return new ServerAnalysisSnapshot(parsed.schemaVersion(), parsed.analyzerVersion(), parsed.parserVersion(),
                    omitted.isEmpty() ? parsed.status() : "PARTIAL", List.copyOf(files), parsed.findings(), parsed.sqlUses(),
                    parsed.authorizationContexts(), List.copyOf(limitations), ServerFlowFinding.connect(parsed), parsed.httpUses())
                    .withSelectionCoverage(selection).withDeploymentAnalysis(deployment).withResourceUses(parsed.resourceUses());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return unavailable("UNAVAILABLE", unavailableFiles, "ANALYSIS_INTERRUPTED").withSelectionCoverage(selection);
        } catch (Exception failure) {
            // Never expose source, child stderr or process environment in an API error or log.
            return unavailable("UNAVAILABLE", unavailableFiles, "PARSER_PROCESS_OR_RESPONSE_FAILED").withSelectionCoverage(selection);
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
                try { process.waitFor(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            io.shutdownNow(); capacity.release();
        }
    }

    private ServerAnalysisSnapshot unavailable(String status, List<FileCoverage> files, String reason) {
        return new ServerAnalysisSnapshot(1, "py-django-v4", null, status, files, List.of(), List.of(), List.of(), List.of(reason), List.of(), List.of());
    }

    private FileCoverage skipped(String path, String reason) {
        return new FileCoverage(path, "LIMIT_EXCEEDED", "NOT_RUN", 0, 0, List.of(reason));
    }

    private void validate(ServerAnalysisSnapshot result, Map<String, Integer> files) {
        if (result.schemaVersion() != 1 || !"py-django-v4".equals(result.analyzerVersion()) || result.parserVersion() == null || !result.parserVersion().matches("CPython-3\\.\\d+\\.\\d+")
                || result.files().size() != files.size() || result.findings().size() > 200 || result.sqlUses().size() > 200
                || result.httpUses() == null || result.httpUses().size() > 200
                || result.resourceUses() == null || result.resourceUses().size() > 200
                || result.authorizationContexts().size() > 200) throw new IllegalArgumentException("INVALID_ANALYZER_RESPONSE");
        if (!result.files().stream().map(FileCoverage::filePath).collect(java.util.stream.Collectors.toSet()).equals(files.keySet()))
            throw new IllegalArgumentException("INVALID_ANALYZER_FILES");
        var locations = new ArrayList<ServerAnalysisSnapshot.Location>();
        if (result.deploymentAnalysis() != null) {
            var config = result.deploymentAnalysis();
            if (config.schemaVersion() != 1 || !"deployment-v1".equals(config.analyzerVersion()) || config.files().size() > files.size() + 1
                    || !config.findings().isEmpty()) throw new IllegalArgumentException("INVALID_SETTINGS_RESPONSE");
            for (var file : config.files()) {
                if (!files.containsKey(file.filePath()) || file.observations().size() > 7) throw new IllegalArgumentException("INVALID_SETTINGS_FILE");
                for (var observation : file.observations()) if (observation.line() < 1 || observation.line() > files.get(file.filePath()))
                    throw new IllegalArgumentException("INVALID_SETTINGS_LOCATION");
            }
        }
        result.findings().forEach(f -> { locations.add(f.source()); locations.add(f.sink()); locations.addAll(f.flow()); locations.addAll(f.defenses()); });
        result.sqlUses().forEach(s -> { locations.add(s.location()); locations.addAll(s.trace()); locations.addAll(s.defenses());
            if (s.executionLocations() != null) locations.addAll(s.executionLocations()); });
        result.httpUses().forEach(s -> { locations.add(s.location()); locations.addAll(s.trace()); locations.addAll(s.defenses()); });
        result.resourceUses().forEach(s -> { locations.add(s.location()); locations.addAll(s.trace()); locations.addAll(s.defenses()); });
        result.authorizationContexts().forEach(c -> { locations.add(c.entry()); locations.addAll(c.checks()); locations.addAll(c.defenses()); locations.addAll(c.resources()); });
        for (var context : result.authorizationContexts()) {
            var details = context.details();
            if (details == null) throw new IllegalArgumentException("MISSING_AUTHORIZATION_DETAILS");
            if (details.permissionDeclarations().size() > 40 || details.principalReferences().size() > 40
                    || details.ownershipComparisons().size() > 40 || details.accesses().size() > 40)
                throw new IllegalArgumentException("INVALID_AUTHORIZATION_LIMIT");
            locations.addAll(details.principalReferences()); locations.addAll(details.ownershipComparisons());
            for (var declaration : details.permissionDeclarations()) {
                if (declaration.permissions().size() > 20) throw new IllegalArgumentException("INVALID_PERMISSION_LIMIT");
                locations.add(declaration.location());
            }
            for (var access : details.accesses()) {
                if (access.identifierInputs().size() > 40 || access.checks().size() > 20) throw new IllegalArgumentException("INVALID_ACCESS_LIMIT");
                locations.add(access.location()); locations.add(access.resourceLocation()); locations.addAll(access.identifierInputs()); locations.addAll(access.checks());
            }
        }
        for (var location : locations) if (location == null || !files.containsKey(location.filePath()) || location.line() < 1
                || location.line() > files.get(location.filePath())) throw new IllegalArgumentException("INVALID_ANALYZER_LOCATION");
    }
}
