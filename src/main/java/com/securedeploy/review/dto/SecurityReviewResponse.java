package com.securedeploy.review.dto;

import java.util.List;
import com.securedeploy.sca.model.ScaResult;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.securedeploy.risk.model.RiskAssessment;

public record SecurityReviewResponse(
        Long reviewId,
        Long projectId,
        String projectName,
        int scannedFileCount,
        int vulnerabilityCount,
        int securityScore,
        String deploymentStatus,
        List<VulnerabilityResultResponse> vulnerabilities,
        ScaResult sca,
        RiskAssessment riskAssessment,
        com.securedeploy.ai.remediation.RemediationSnapshot remediation,
        com.securedeploy.ai.semantic.SemanticSnapshot semanticReview,
        com.securedeploy.review.model.ScanMode scanMode,
        com.securedeploy.review.model.ReviewSourceType sourceType,
        String repositoryUrl,
        java.time.LocalDateTime createdAt,
        com.securedeploy.project.progress.ReviewProgressSnapshot comparison,
        com.securedeploy.github.model.GitHubSourceSnapshot sourceMetadata,
        com.securedeploy.project.coverage.CoverageLedger coverage,
        com.securedeploy.analysis.typescript.ServerAnalysisSnapshot serverAnalysis
) {
    @JsonProperty(value="workspaceScan", access=JsonProperty.Access.READ_ONLY)
    public com.securedeploy.editing.WorkspaceScanSnapshot workspaceScan() {
        return comparison == null ? null : comparison.workspaceScan();
    }
    @JsonProperty(value="resultSummary", access=JsonProperty.Access.READ_ONLY)
    public ReviewResultSummary resultSummary() {
        return ReviewResultSummary.from(this);
    }

    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
            int vulnerabilityCount, int securityScore, String deploymentStatus, List<VulnerabilityResultResponse> vulnerabilities,
            ScaResult sca, RiskAssessment riskAssessment, com.securedeploy.ai.remediation.RemediationSnapshot remediation,
            com.securedeploy.ai.semantic.SemanticSnapshot semanticReview, com.securedeploy.review.model.ScanMode scanMode,
            com.securedeploy.review.model.ReviewSourceType sourceType, String repositoryUrl, java.time.LocalDateTime createdAt,
            com.securedeploy.project.progress.ReviewProgressSnapshot comparison, com.securedeploy.github.model.GitHubSourceSnapshot sourceMetadata,
            com.securedeploy.project.coverage.CoverageLedger coverage) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore, deploymentStatus,
                vulnerabilities, sca, riskAssessment, remediation, semanticReview, scanMode, sourceType, repositoryUrl, createdAt,
                comparison, sourceMetadata, coverage, null);
    }

    public SecurityReviewResponse withServerAnalysis(com.securedeploy.analysis.typescript.ServerAnalysisSnapshot value) {
        return new SecurityReviewResponse(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore,
                deploymentStatus, vulnerabilities, sca, riskAssessment, remediation, semanticReview, scanMode,
                sourceType, repositoryUrl, createdAt, comparison, sourceMetadata, coverage, value);
    }
    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
            int vulnerabilityCount, int securityScore, String deploymentStatus, List<VulnerabilityResultResponse> vulnerabilities,
            ScaResult sca, RiskAssessment riskAssessment, com.securedeploy.ai.remediation.RemediationSnapshot remediation,
            com.securedeploy.ai.semantic.SemanticSnapshot semanticReview, com.securedeploy.review.model.ScanMode scanMode,
            com.securedeploy.review.model.ReviewSourceType sourceType, String repositoryUrl, java.time.LocalDateTime createdAt,
            com.securedeploy.project.progress.ReviewProgressSnapshot comparison, com.securedeploy.github.model.GitHubSourceSnapshot sourceMetadata) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore, deploymentStatus,
                vulnerabilities, sca, riskAssessment, remediation, semanticReview, scanMode, sourceType, repositoryUrl, createdAt, comparison, sourceMetadata, null);
    }

    public SecurityReviewResponse withCoverage(com.securedeploy.project.coverage.CoverageLedger value) {
        return new SecurityReviewResponse(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore,
                deploymentStatus, vulnerabilities, sca, riskAssessment, remediation, semanticReview, scanMode,
                sourceType, repositoryUrl, createdAt, comparison, sourceMetadata, value, serverAnalysis);
    }
    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
            int vulnerabilityCount, int securityScore, String deploymentStatus,
            List<VulnerabilityResultResponse> vulnerabilities, ScaResult sca, RiskAssessment riskAssessment,
            com.securedeploy.ai.remediation.RemediationSnapshot remediation,
            com.securedeploy.ai.semantic.SemanticSnapshot semanticReview, com.securedeploy.review.model.ScanMode scanMode) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore, deploymentStatus,
                vulnerabilities, sca, riskAssessment, remediation, semanticReview, scanMode, null, null, null, null, null);
    }
    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
                                  int vulnerabilityCount, int securityScore, String deploymentStatus,
                                  List<VulnerabilityResultResponse> vulnerabilities, ScaResult sca, RiskAssessment riskAssessment,
                                  com.securedeploy.ai.remediation.RemediationSnapshot remediation,
                                  com.securedeploy.ai.semantic.SemanticSnapshot semanticReview) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore,
                deploymentStatus, vulnerabilities, sca, riskAssessment, remediation, semanticReview, null);
    }
    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
                                  int vulnerabilityCount, int securityScore, String deploymentStatus,
                                  List<VulnerabilityResultResponse> vulnerabilities, ScaResult sca, RiskAssessment riskAssessment,
                                  com.securedeploy.ai.remediation.RemediationSnapshot remediation) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore,
                deploymentStatus, vulnerabilities, sca, riskAssessment, remediation, null);
    }

    public SecurityReviewResponse withSemanticReview(com.securedeploy.ai.semantic.SemanticSnapshot snapshot) {
        return new SecurityReviewResponse(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount,
                securityScore, deploymentStatus, vulnerabilities, sca, riskAssessment, remediation, snapshot, scanMode,
                sourceType, repositoryUrl, createdAt, comparison, sourceMetadata, coverage, serverAnalysis);
    }
    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
                                  int vulnerabilityCount, int securityScore, String deploymentStatus,
                                  List<VulnerabilityResultResponse> vulnerabilities, ScaResult sca, RiskAssessment riskAssessment) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore,
                deploymentStatus, vulnerabilities, sca, riskAssessment, null);
    }

    public SecurityReviewResponse withRemediation(com.securedeploy.ai.remediation.RemediationSnapshot snapshot) {
        return new SecurityReviewResponse(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount,
                securityScore, deploymentStatus, vulnerabilities, sca, riskAssessment, snapshot, semanticReview, scanMode,
                sourceType, repositoryUrl, createdAt, comparison, sourceMetadata, coverage, serverAnalysis);
    }
    @JsonProperty("deploymentAssessmentScope")
    public String deploymentAssessmentScope() {
        return "RULE_ENGINE_ONLY";
    }

    @JsonProperty("assessmentInterpretation")
    public AssessmentInterpretation assessmentInterpretation() {
        return new AssessmentInterpretation("riskAssessment.prioritizedDeploymentAssessment", riskAssessment != null,
                "RULE_ENGINE_REFERENCE_ONLY", "LEGACY_RULE_ENGINE_REFERENCE", false,
                "보안 점수는 기존 Rule Engine 중심 참고값입니다. 배포 판단은 Code, SCA, 저장된 악용 정보 및 분석 완성도를 고려한 위험 기반 평가를 우선합니다. 위험 평가가 없으면 재분석이 필요합니다.");
    }

    public record AssessmentInterpretation(String primaryAssessmentField, boolean primaryAssessmentAvailable,
                                           String securityScoreRole, String legacyDeploymentStatusRole,
                                           boolean securityScoreDeterminesDeployment, String message) { }

    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
                                  int vulnerabilityCount, int securityScore, String deploymentStatus,
                                  List<VulnerabilityResultResponse> vulnerabilities, ScaResult sca) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore,
                deploymentStatus, vulnerabilities, sca, null);
    }

    public SecurityReviewResponse(Long reviewId, Long projectId, String projectName, int scannedFileCount,
                                  int vulnerabilityCount, int securityScore, String deploymentStatus,
                                  List<VulnerabilityResultResponse> vulnerabilities) {
        this(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount, securityScore,
                deploymentStatus, vulnerabilities, null);
    }

    public SecurityReviewResponse withSca(ScaResult result) {
        return new SecurityReviewResponse(reviewId, projectId, projectName, scannedFileCount,
                vulnerabilityCount, securityScore, deploymentStatus, vulnerabilities, result, riskAssessment, remediation, semanticReview, scanMode,
                sourceType, repositoryUrl, createdAt, comparison, sourceMetadata, coverage, serverAnalysis);
    }

    public SecurityReviewResponse withReviewId(Long reviewId) {
        return withReviewIdAndProjectId(reviewId, projectId);
    }

    public SecurityReviewResponse withReviewIdAndProjectId(Long reviewId, Long projectId) {
        return new SecurityReviewResponse(
                reviewId,
                projectId,
                projectName,
                scannedFileCount,
                vulnerabilityCount,
                securityScore,
                deploymentStatus,
                vulnerabilities,
                sca,
                riskAssessment,
                remediation,
                semanticReview,
                scanMode, sourceType, repositoryUrl, createdAt, comparison, sourceMetadata, coverage, serverAnalysis
        );
    }

    public SecurityReviewResponse withSourceMetadata(com.securedeploy.github.model.GitHubSourceSnapshot value) {
        return new SecurityReviewResponse(reviewId, projectId, projectName, scannedFileCount, vulnerabilityCount,
                securityScore, deploymentStatus, vulnerabilities, sca, riskAssessment, remediation, semanticReview,
                scanMode, sourceType, repositoryUrl, createdAt, comparison, value, coverage, serverAnalysis);
    }
}
