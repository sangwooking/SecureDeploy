package com.securedeploy.ai.semantic;

import com.securedeploy.ai.dto.AiConfidence;
import java.time.Instant;
import java.util.List;

public record SemanticCandidate(String candidateId, String sliceId, CandidateType candidateType, String title,
                                AiConfidence semanticAnalysisConfidence, String reason, boolean verificationRequired,
                                List<Evidence> evidence, List<String> verificationSteps,
                                List<String> relatedExistingFindingIds, Instant generatedAt,
                                String provider, String model, String promptVersion) {
    @com.fasterxml.jackson.annotation.JsonProperty(value = "findingType", access = com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY)
    public String findingType() { return "AI_SECURITY_CANDIDATE"; }
    @com.fasterxml.jackson.annotation.JsonProperty(value = "reviewStatus", access = com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY)
    public String reviewStatus() { return "REVIEW_REQUIRED"; }
    public enum CandidateType {
        AUTHORIZATION_BYPASS, IDOR, MISSING_AUTHENTICATION, BROKEN_ACCESS_CONTROL,
        BUSINESS_LOGIC_BYPASS, UNSAFE_FILE_ACCESS, PATH_TRAVERSAL_CANDIDATE, SSRF_CANDIDATE,
        COMMAND_INJECTION_CANDIDATE, UNSAFE_DESERIALIZATION, SENSITIVE_DATA_EXPOSURE,
        CRYPTO_MISUSE, SESSION_SECURITY, OTHER_SECURITY_CONCERN
    }
    public record Evidence(String contextId, String filePath, int startLine, int endLine,
                           String functionName, String evidenceDescription) { }
    // Only this untrusted transport shape is accepted from a provider. Provenance is server-owned.
    public record Proposal(String sliceId, CandidateType candidateType, String title, AiConfidence semanticAnalysisConfidence,
                           String reason, boolean verificationRequired, List<Evidence> evidence,
                           List<String> verificationSteps, List<String> relatedExistingFindingIds) { }
}
