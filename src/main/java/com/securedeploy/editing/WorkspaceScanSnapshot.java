package com.securedeploy.editing;

import java.time.Instant;
import java.util.List;

/** Provenance only: never contains source bytes, credentials, or AI prompt text. */
public record WorkspaceScanSnapshot(int schemaVersion, String workspaceId, long userId, long originalReviewId,
        long revision, String sourceRevision, String identityStatus, String inputHash,
        Instant capturedAt, String analyzerVersion, boolean baselineVerified, List<File> files, String analysisRoot,List<EditingWorkspaceService.ExportApproval> exports) {
    public WorkspaceScanSnapshot { exports=exports==null?List.of():List.copyOf(exports); }
    public WorkspaceScanSnapshot(int schemaVersion,String workspaceId,long userId,long originalReviewId,long revision,String sourceRevision,String identityStatus,String inputHash,Instant capturedAt,String analyzerVersion,boolean baselineVerified,List<File> files,String analysisRoot){this(schemaVersion,workspaceId,userId,originalReviewId,revision,sourceRevision,identityStatus,inputHash,capturedAt,analyzerVersion,baselineVerified,files,analysisRoot,List.of());}
    @com.fasterxml.jackson.annotation.JsonProperty(value="provenanceHash",access=com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY) public String provenanceHash(){return EditingWorkspaceService.provenanceHash(files);}
    public record File(String fileId, String path, String originalHash, String currentHash,
                       boolean changed, String changeOrigin,List<ChangeAttribution> provenance) {
        public File { provenance=provenance==null?List.of():List.copyOf(provenance); }
        public File(String fileId,String path,String originalHash,String currentHash,boolean changed,String changeOrigin){this(fileId,path,originalHash,currentHash,changed,changeOrigin,List.of());}
    }
    public WorkspaceScanSnapshot withAnalyzer(String version) {
        return new WorkspaceScanSnapshot(schemaVersion, workspaceId, userId, originalReviewId, revision, sourceRevision,
                identityStatus, inputHash, capturedAt, version, baselineVerified, files, analysisRoot,exports);
    }
    public WorkspaceScanSnapshot withAnalysisRoot(String root) {
        return new WorkspaceScanSnapshot(schemaVersion, workspaceId, userId, originalReviewId, revision, sourceRevision,
                identityStatus, inputHash, capturedAt, analyzerVersion, baselineVerified, files, root,exports);
    }
}
