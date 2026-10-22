package com.securedeploy.project.progress;

import com.securedeploy.ai.semantic.SemanticCandidate;
import com.securedeploy.risk.model.DeploymentAssessment;
import com.securedeploy.risk.model.RiskFinding;
import com.securedeploy.risk.model.RiskPriority;
import com.securedeploy.review.dto.VulnerabilityResultResponse;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public record ReviewProgressSnapshot(int comparisonSchemaVersion, Long projectId, Long baselineReviewId,
        Long currentReviewId, LocalDateTime baselineAnalyzedAt, LocalDateTime currentAnalyzedAt,
        Instant generatedAt, Status status, String message, Assessment assessmentBefore,
        Assessment assessmentAfter, Map<Change, Long> counts, List<Entry> findings,
        List<AiEntry> aiChanges, List<String> notices,
        com.securedeploy.github.model.GitHubSourceSnapshot sourceBefore,
        com.securedeploy.github.model.GitHubSourceSnapshot sourceAfter,
        com.securedeploy.editing.WorkspaceScanSnapshot workspaceScan) {
    public ReviewProgressSnapshot(int comparisonSchemaVersion, Long projectId, Long baselineReviewId,
            Long currentReviewId, LocalDateTime baselineAnalyzedAt, LocalDateTime currentAnalyzedAt,
            Instant generatedAt, Status status, String message, Assessment assessmentBefore,
            Assessment assessmentAfter, Map<Change, Long> counts, List<Entry> findings,
            List<AiEntry> aiChanges, List<String> notices,
            com.securedeploy.github.model.GitHubSourceSnapshot sourceBefore,
            com.securedeploy.github.model.GitHubSourceSnapshot sourceAfter) {
        this(comparisonSchemaVersion, projectId, baselineReviewId, currentReviewId, baselineAnalyzedAt,
                currentAnalyzedAt, generatedAt, status, message, assessmentBefore, assessmentAfter, counts,
                findings, aiChanges, notices, sourceBefore, sourceAfter, null);
    }
    public enum Status { COMPLETE, PARTIAL, UNAVAILABLE, NO_BASELINE }
    public enum Change { RESOLVED, REMAINING, NEW, CHANGED, UNAVAILABLE }
    public enum AiChange { REMAINING, NEW, NOT_REOBSERVED, UNAVAILABLE }
    public record Assessment(DeploymentAssessment deploymentAssessment, Map<RiskPriority, Long> prioritySummary,
                             int semanticCandidateCount, int referenceSecurityScore) { }
    public record Finding(RiskFinding risk, VulnerabilityResultResponse code) { }
    public record Entry(String fingerprint, Change status, Finding before, Finding after,
                        List<String> currentVersions, String note) { }
    public record AiEntry(String fingerprint, AiChange status, SemanticCandidate before,
                          SemanticCandidate after, String note) { }
}
