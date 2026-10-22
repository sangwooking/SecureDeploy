package com.securedeploy.project.progress;

import java.util.List;

/** Coverage facts only; no uploaded source or credential is retained here. */
public record ComparisonContext(int schemaVersion, Long baselineReviewId, String analyzerVersion,
                                boolean ruleAnalysisComplete, List<String> analyzedFiles,
                                com.securedeploy.editing.WorkspaceScanSnapshot workspaceScan) {
    public ComparisonContext(int schemaVersion, Long baselineReviewId, String analyzerVersion,
            boolean ruleAnalysisComplete, List<String> analyzedFiles) {
        this(schemaVersion, baselineReviewId, analyzerVersion, ruleAnalysisComplete, analyzedFiles, null);
    }
    public ComparisonContext withBaseline(Long id) {
        return new ComparisonContext(schemaVersion, id, analyzerVersion, ruleAnalysisComplete, analyzedFiles, workspaceScan);
    }
    public ComparisonContext forWorkspace(com.securedeploy.editing.WorkspaceScanSnapshot source) {
        return new ComparisonContext(schemaVersion, source.baselineVerified() ? source.originalReviewId() : null,
                analyzerVersion, ruleAnalysisComplete, analyzedFiles, source.withAnalyzer(analyzerVersion));
    }
}
