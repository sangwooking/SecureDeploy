package com.securedeploy.ai.semantic;

import com.securedeploy.ai.dto.AiUsageResponse;
import com.securedeploy.review.model.ScanMode;
import java.time.Instant;
import java.util.List;

public record SemanticSnapshot(int schemaVersion, String snapshotId, ScanMode scanMode,
                               Status semanticReviewStatus, List<SemanticCandidate> candidates,
                               List<SemanticCandidate> existingFindingEvidence,
                               List<SecuritySlice.Metadata> slices, int semanticSlicesAnalyzed,
                               int omittedSlices, int rejectedCandidates, int deduplicatedCandidates,
                               String validationStatus, String provider, String model, String promptVersion,
                               Instant generatedAt, int requestCount, AiUsageResponse usage, List<String> notices) {
    public enum Status { NOT_REQUESTED, UNAVAILABLE, NO_SUPPORTED_CONTEXT, COMPLETED, PARTIAL, FAILED, REJECTED }
}
