package com.securedeploy.project.progress;

import java.util.List;

/** Coverage facts only; no uploaded source or credential is retained here. */
public record ComparisonContext(int schemaVersion, Long baselineReviewId, String analyzerVersion,
                                boolean ruleAnalysisComplete, List<String> analyzedFiles,
                                com.securedeploy.editing.WorkspaceScanSnapshot workspaceScan, ComparisonEvidence evidence) {
    public ComparisonContext(int schemaVersion, Long baselineReviewId, String analyzerVersion, boolean ruleAnalysisComplete, List<String> analyzedFiles, com.securedeploy.editing.WorkspaceScanSnapshot workspaceScan) { this(schemaVersion,baselineReviewId,analyzerVersion,ruleAnalysisComplete,analyzedFiles,workspaceScan,null); }
    public ComparisonContext(int schemaVersion, Long baselineReviewId, String analyzerVersion,
            boolean ruleAnalysisComplete, List<String> analyzedFiles) {
        this(schemaVersion, baselineReviewId, analyzerVersion, ruleAnalysisComplete, analyzedFiles, null);
    }
    public ComparisonContext withBaseline(Long id) {
        return new ComparisonContext(schemaVersion, id, analyzerVersion, ruleAnalysisComplete, analyzedFiles, workspaceScan, evidence);
    }
    public ComparisonContext forWorkspace(com.securedeploy.editing.WorkspaceScanSnapshot source) {
        return new ComparisonContext(schemaVersion, source.baselineVerified() ? source.originalReviewId() : null,
                analyzerVersion, ruleAnalysisComplete, analyzedFiles, source.withAnalyzer(analyzerVersion), evidence);
    }
}
