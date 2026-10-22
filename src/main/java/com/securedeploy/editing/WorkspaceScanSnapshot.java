package com.securedeploy.editing;

import java.time.Instant;
import java.util.List;

/** Provenance only: never contains source bytes, credentials, or AI prompt text. */
public record WorkspaceScanSnapshot(int schemaVersion, String workspaceId, long userId, long originalReviewId,
        long revision, String sourceRevision, String identityStatus, String inputHash,
        Instant capturedAt, String analyzerVersion, boolean baselineVerified, List<File> files, String analysisRoot) {
    public record File(String fileId, String path, String originalHash, String currentHash,
                       boolean changed, String changeOrigin) { }
    public WorkspaceScanSnapshot withAnalyzer(String version) {
        return new WorkspaceScanSnapshot(schemaVersion, workspaceId, userId, originalReviewId, revision, sourceRevision,
                identityStatus, inputHash, capturedAt, version, baselineVerified, files, analysisRoot);
    }
    public WorkspaceScanSnapshot withAnalysisRoot(String root) {
        return new WorkspaceScanSnapshot(schemaVersion, workspaceId, userId, originalReviewId, revision, sourceRevision,
                identityStatus, inputHash, capturedAt, analyzerVersion, baselineVerified, files, root);
    }
}
