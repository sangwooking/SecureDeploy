package com.securedeploy.project.coverage;

import java.util.List;
import java.util.Map;

/** Execution evidence, not a safety score or a claim of whole-language analysis. */
public record CoverageLedger(int schemaVersion, String policyVersion, String status,
        int discoveredFiles, int selectedFiles, int unsupportedFiles, int excludedFiles,
        int failedFiles, boolean inventoryComplete, int omittedEntries,
        List<Entry> entries, List<Analyzer> analyzers, InspectionScope inspectionScope) {
    public CoverageLedger(int schemaVersion, String policyVersion, String status, int discoveredFiles,
            int selectedFiles, int unsupportedFiles, int excludedFiles, int failedFiles, boolean inventoryComplete,
            int omittedEntries, List<Entry> entries, List<Analyzer> analyzers) {
        this(schemaVersion, policyVersion, status, discoveredFiles, selectedFiles, unsupportedFiles, excludedFiles,
                failedFiles, inventoryComplete, omittedEntries, entries, analyzers, null);
    }
    public record Entry(String filePath, String kind, String fileType, String status, String reason) { }
    public record Analyzer(String analyzer, String status, String scope, Map<String, Integer> fileStatuses) { }
    public CoverageLedger withAnalyzers(List<Analyzer> value) {
        return new CoverageLedger(schemaVersion, policyVersion, status, discoveredFiles, selectedFiles,
                unsupportedFiles, excludedFiles, failedFiles, inventoryComplete, omittedEntries, entries, List.copyOf(value), inspectionScope);
    }
    public CoverageLedger withInspectionScope(InspectionScope value) {
        boolean partial = value != null && (!value.evidenceComplete() || !value.incompleteAnalyzers().isEmpty()
                || value.areas().stream().anyMatch(a -> !List.of("ROOT_DECLARED", "NON_ROOT_DECLARED").contains(a.status())));
        String scopedStatus = "COMPLETE".equals(status) && partial ? "PARTIAL" : status;
        return new CoverageLedger(schemaVersion, policyVersion, scopedStatus, discoveredFiles, selectedFiles,
                unsupportedFiles, excludedFiles, failedFiles, inventoryComplete, omittedEntries, entries, analyzers, value);
    }
}
