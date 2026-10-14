package com.securedeploy.project.progress;

import java.util.List;

/** Coverage facts only; no uploaded source or credential is retained here. */
public record ComparisonContext(int schemaVersion, Long baselineReviewId, String analyzerVersion,
                                boolean ruleAnalysisComplete, List<String> analyzedFiles) {
    public ComparisonContext withBaseline(Long id) {
        return new ComparisonContext(schemaVersion, id, analyzerVersion, ruleAnalysisComplete, analyzedFiles);
    }
}
