package com.securedeploy.analysis.typescript;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import com.securedeploy.project.coverage.CoverageLedger;

/** Structural evidence is deliberately outside the legacy score and risk policy. */
public record ServerAnalysisSnapshot(int schemaVersion, String analyzerVersion, String parserVersion,
        String status, List<FileCoverage> files, List<Finding> findings, List<SqlUse> sqlUses,
        List<AuthorizationContext> authorizationContexts, List<String> limitations,
        List<ServerFlowFinding> validatedFindings, List<HttpUse> httpUses) {
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
            Integer httpCallSites, Integer tracedHttpCallSites) {
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
        });
        var analyzers = new java.util.ArrayList<>(ledger.analyzers());
        analyzers.add(new CoverageLedger.Analyzer("TYPESCRIPT_SERVER", status,
                "Workers/Pages 진입점의 제한된 구문·값 전달 검사. 전체 TypeScript, 실행 가능성, 인증·소유권 보증 및 Risk 계산에는 포함되지 않습니다.", counts));
        String combined = "FAILED".equals(ledger.status()) ? "FAILED"
                : !List.of("COMPLETE", "NOT_APPLICABLE").contains(status) ? "PARTIAL" : ledger.status();
        return new CoverageLedger(ledger.schemaVersion(), ledger.policyVersion(), combined, ledger.discoveredFiles(),
                ledger.selectedFiles(), ledger.unsupportedFiles(), ledger.excludedFiles(), ledger.failedFiles(),
                ledger.inventoryComplete(), ledger.omittedEntries(), ledger.entries(), List.copyOf(analyzers));
    }
}
