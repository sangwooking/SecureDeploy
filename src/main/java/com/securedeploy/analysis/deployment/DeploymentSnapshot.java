package com.securedeploy.analysis.deployment;

import com.securedeploy.project.coverage.CoverageLedger;
import java.util.*;

/** Sanitized declaration evidence, not a reconstructed runtime or a new risk policy. */
public record DeploymentSnapshot(int schemaVersion, String analyzerVersion, String status,
        List<FileResult> files, List<Finding> findings, List<String> limitations) {
    public record Observation(int line, String scope, String setting, String valueStatus,
            String valueSummary, String ruleId) { }
    public record FileResult(String filePath, String format, String status,
            List<Observation> observations, List<String> limitations) { }
    public record Finding(String findingId, String sourceType, String priority, String comparisonPolicy,
            String filePath, int line, String scope, String setting, String ruleId,
            String valueSummary, String title, String reason, String recommendation,
            List<String> verificationSteps) { }

    public CoverageLedger attachCoverage(CoverageLedger ledger) {
        var counts = new TreeMap<String, Integer>();
        files.forEach(f -> counts.merge(f.format() + ":" + f.status(), 1, Integer::sum));
        var analyzers = new ArrayList<>(ledger.analyzers());
        analyzers.add(new CoverageLedger.Analyzer("DEPLOYMENT_CONFIG", status,
                "Compose 서비스·Django 리터럴·Wrangler 환경별 선언 검사. 실제 활성 환경·override·네트워크 노출은 미검증. 기존 Risk와 별도 검토 항목입니다.", counts));
        return new CoverageLedger(ledger.schemaVersion(), ledger.policyVersion(),
                "FAILED".equals(ledger.status()) ? "FAILED" : files.isEmpty() ? ledger.status() : "PARTIAL",
                ledger.discoveredFiles(), ledger.selectedFiles(), ledger.unsupportedFiles(), ledger.excludedFiles(),
                ledger.failedFiles(), ledger.inventoryComplete(), ledger.omittedEntries(), ledger.entries(), analyzers, ledger.inspectionScope());
    }
}
