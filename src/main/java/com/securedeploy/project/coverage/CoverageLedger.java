package com.securedeploy.project.coverage;

import java.util.List;
import java.util.Map;

/** Execution evidence, not a safety score or a claim of whole-language analysis. */
public record CoverageLedger(int schemaVersion, String policyVersion, String status,
        int discoveredFiles, int selectedFiles, int unsupportedFiles, int excludedFiles,
        int failedFiles, boolean inventoryComplete, int omittedEntries,
        List<Entry> entries, List<Analyzer> analyzers) {
    public record Entry(String filePath, String kind, String fileType, String status, String reason) { }
    public record Analyzer(String analyzer, String status, String scope, Map<String, Integer> fileStatuses) { }
    public CoverageLedger withAnalyzers(List<Analyzer> value) {
        return new CoverageLedger(schemaVersion, policyVersion, status, discoveredFiles, selectedFiles,
                unsupportedFiles, excludedFiles, failedFiles, inventoryComplete, omittedEntries, entries, List.copyOf(value));
    }
}
