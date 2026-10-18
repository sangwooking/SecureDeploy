package com.securedeploy.analysis.typescript;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import com.securedeploy.project.coverage.CoverageLedger;

/** Structural evidence is deliberately outside the legacy score and risk policy. */
public record ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
        String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
        List<AuthorizationContext> authorizationContexts, List<String> limitations,
        List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses, ServerAnalysisSnapshot pythonAnalysis,
        SelectionCoverage selectionCoverage) {
    public record SelectionCoverage(int discoveredFiles, int submittedFiles, int omittedFiles, int omittedDetails,
            int submittedCharacters, Map<String, Integer> omissionReasons) { }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations,
            List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses, ServerAnalysisSnapshot pythonAnalysis) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, httpUses, pythonAnalysis, null);
    }
    public ServerAnalysisSnapshot withSelectionCoverage(SelectionCoverage selection) {
        return new ServerAnalysisSnapshot(schemaVersion, analyzerVersion, parserVersion, status, files, findings,
                sqlUses, authorizationContexts, limitations, validatedFindings, httpUses, pythonAnalysis, selection);
    }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations,
            List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, httpUses, null);
    }
    public ServerAnalysisSnapshot withPythonAnalysis(ServerAnalysisSnapshot value) {
        return new ServerAnalysisSnapshot(schemaVersion, analyzerVersion, parserVersion, status, files, findings,
                sqlUses, authorizationContexts, limitations, validatedFindings, httpUses, value, selectionCoverage);
    }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations, List<ServerFlowFinding> validatedFindings) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, validatedFindings, null);
    }
    public ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
            String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
            List<AuthorizationContext> authorizationContexts, List<String> limitations) {
        this(schemaVersion, analyzerVersion, parserVersion, status, files, findings, sqlUses,
                authorizationContexts, limitations, null, null);
    }
    public record Location(String filePath, int line, int column, String functionName, String kind) { }
    public record FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
            int functionsAnalyzed, int prepareCallSites, int tracedPrepareCallSites, List<String> limitations,
            Integer httpCallSites, Integer tracedHttpCallSites, String selectionReason) {
        public FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
                int functionsAnalyzed, int prepareCallSites, int tracedPrepareCallSites, List<String> limitations,
                Integer httpCallSites, Integer tracedHttpCallSites) {
            this(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed, prepareCallSites,
                    tracedPrepareCallSites, limitations, httpCallSites, tracedHttpCallSites, null);
        }
        public FileCoverage withSelectionReason(String reason) {
            return new FileCoverage(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed,
                    prepareCallSites, tracedPrepareCallSites, limitations, httpCallSites, tracedHttpCallSites, reason);
        }
        public FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
                int functionsAnalyzed, int prepareCallSites, int tracedPrepareCallSites, List<String> limitations) {
            this(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed, prepareCallSites, tracedPrepareCallSites, limitations, null, null);
        }
        public FileCoverage(String filePath, String parseStatus, String flowStatus, int entrypoints,
                int functionsAnalyzed, List<String> limitations) {
            this(filePath, parseStatus, flowStatus, entrypoints, functionsAnalyzed, 0, 0, limitations);
        }
    }
    public record Finding(String ruleId, String kind, String confidence, String disposition,
            Location source, Location sink, List<Location> flow, List<Location> defenses,
            List<String> limitations, String message, String recommendation) { }
    public record SqlUse(String kind, Location location, List<Location> trace, List<Location> defenses,
            List<String> limitations, boolean executionObserved, List<Location> executionLocations) { }
    public record HttpUse(String kind, String controlledPart, Location location, List<Location> trace,
            List<Location> defenses, List<String> limitations) { }
    public record AuthorizationContext(Location entry, List<Location> checks, List<Location> defenses,
            List<Location> resources, String conclusion, List<String> limitations) { }

    public static ServerAnalysisSnapshot unavailable(String status, List<FileCoverage> files, String reason) {
        return new ServerAnalysisSnapshot(1, "ts-server-v4", null, status, files, List.of(), List.of(), List.of(), List.of(reason));
    }

    public CoverageLedger attachCoverage(CoverageLedger ledger) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        files.forEach(file -> {
            counts.merge("AST_" + file.parseStatus(), 1, Integer::sum);
            counts.merge("FLOW_" + file.flowStatus(), 1, Integer::sum);
            if (analyzerVersion.startsWith("py-django-")) {
                counts.merge("ENTRYPOINTS", file.entrypoints(), Integer::sum);
                counts.merge("FUNCTIONS_TRACED", file.functionsAnalyzed(), Integer::sum);
                file.limitations().forEach(reason -> counts.merge("LIMITATION_" + reason, 1, Integer::sum));
            }
        });
        if (selectionCoverage != null) {
            counts.put("DISCOVERED_PYTHON_FILES", selectionCoverage.discoveredFiles());
            counts.put("SUBMITTED_PYTHON_FILES", selectionCoverage.submittedFiles());
            counts.put("OMITTED_PYTHON_FILES", selectionCoverage.omittedFiles());
        }
        var analyzers = new java.util.ArrayList<>(ledger.analyzers());
        boolean python = analyzerVersion.startsWith("py-django-");
        analyzers.add(new CoverageLedger.Analyzer(python ? "PYTHON_SERVER" : "TYPESCRIPT_SERVER", status,
                python ? "Django/DRF 진입점의 제한된 SQL 값 전달 검사. 전체 Python, 인증·소유권, 실행 가능성은 보증하지 않으며 기존 Risk 계산과 분리됩니다."
                : "Workers/Pages 진입점의 제한된 구문·값 전달 검사. 전체 TypeScript, 실행 가능성, 인증·소유권 보증 및 Risk 계산에는 포함되지 않습니다.", counts));
        String combined = "FAILED".equals(ledger.status()) ? "FAILED"
                : !List.of("COMPLETE", "NOT_APPLICABLE").contains(status) ? "PARTIAL" : ledger.status();
        return new CoverageLedger(ledger.schemaVersion(), ledger.policyVersion(), combined, ledger.discoveredFiles(),
                ledger.selectedFiles(), ledger.unsupportedFiles(), ledger.excludedFiles(), ledger.failedFiles(),
                ledger.inventoryComplete(), ledger.omittedEntries(), ledger.entries(), List.copyOf(analyzers), ledger.inspectionScope());
    }
}
