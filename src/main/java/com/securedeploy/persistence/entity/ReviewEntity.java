package com.securedeploy.persistence.entity;

import com.securedeploy.review.model.ReviewSourceType;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import com.securedeploy.sca.persistence.ReviewScaEntity;
import com.securedeploy.sca.model.ScaResult;
import com.securedeploy.risk.model.RiskAssessment;
import com.securedeploy.risk.persistence.RiskAssessmentConverter;
import jakarta.persistence.Convert;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "reviews")
public class ReviewEntity {

    @Convert(converter = com.securedeploy.analysis.typescript.ServerAnalysisConverter.class)
    @Column(name = "server_analysis_json", columnDefinition = "TEXT")
    private com.securedeploy.analysis.typescript.ServerAnalysisSnapshot serverAnalysis;

    public com.securedeploy.analysis.typescript.ServerAnalysisSnapshot getServerAnalysis() { return serverAnalysis; }
    public void attachServerAnalysis(com.securedeploy.analysis.typescript.ServerAnalysisSnapshot value) {
        if (serverAnalysis != null) throw new IllegalStateException("Server analysis snapshot is immutable");
        serverAnalysis = value;
    }

    @Convert(converter = com.securedeploy.project.coverage.CoverageLedgerConverter.class)
    @Column(name = "coverage_ledger_json", columnDefinition = "TEXT")
    private com.securedeploy.project.coverage.CoverageLedger coverage;

    public com.securedeploy.project.coverage.CoverageLedger getCoverage() { return coverage; }
    public void attachCoverage(com.securedeploy.project.coverage.CoverageLedger value) {
        if (coverage != null) throw new IllegalStateException("Coverage snapshot is immutable");
        coverage = value;
    }

    @Convert(converter = com.securedeploy.github.model.GitHubSourceSnapshotConverter.class)
    @Column(name = "source_metadata_json", columnDefinition = "TEXT")
    private com.securedeploy.github.model.GitHubSourceSnapshot sourceMetadata;

    public com.securedeploy.github.model.GitHubSourceSnapshot getSourceMetadata() { return sourceMetadata; }
    public void attachSourceMetadata(com.securedeploy.github.model.GitHubSourceSnapshot value) {
        if (sourceMetadata != null) throw new IllegalStateException("Source snapshot is immutable");
        sourceMetadata = value;
    }

    @Convert(converter = com.securedeploy.project.progress.ComparisonContextConverter.class)
    @Column(name = "comparison_context_json", columnDefinition = "TEXT")
    private com.securedeploy.project.progress.ComparisonContext comparisonContext;

    @Convert(converter = com.securedeploy.project.progress.ReviewProgressSnapshotConverter.class)
    @Column(name = "comparison_snapshot_json", columnDefinition = "TEXT")
    private com.securedeploy.project.progress.ReviewProgressSnapshot comparison;

    public com.securedeploy.project.progress.ComparisonContext getComparisonContext() { return comparisonContext; }
    public void attachComparisonContext(com.securedeploy.project.progress.ComparisonContext context) { comparisonContext = context; }
    public com.securedeploy.project.progress.ReviewProgressSnapshot getComparison() { return comparison; }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id")
    private ProjectEntity project;

    @Column(nullable = false)
    private String projectName;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 20, columnDefinition = "varchar(20)")
    private ReviewSourceType sourceType;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "scan_mode", columnDefinition = "varchar(20)")
    private com.securedeploy.review.model.ScanMode scanMode;

    public void assignScanMode(com.securedeploy.review.model.ScanMode mode) { this.scanMode = mode; }
    public com.securedeploy.review.model.ScanMode getScanMode() { return scanMode; }

    @Column(length = 500)
    private String repositoryUrl;

    @Column(nullable = false)
    private int scannedFileCount;

    @Column(nullable = false)
    private int vulnerabilityCount;

    @Column(nullable = false)
    private int securityScore;

    @Column(nullable = false, length = 50)
    private String deploymentStatus;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "review", cascade = CascadeType.ALL, orphanRemoval = true)
    private final List<VulnerabilityEntity> vulnerabilities = new ArrayList<>();

    @OneToMany(mappedBy = "review", cascade = CascadeType.ALL, orphanRemoval = true)
    private final List<ReviewSnippetEntity> snippets = new ArrayList<>();

    @OneToOne(mappedBy = "review", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    private ReviewScaEntity scaReport;

    @Convert(converter = RiskAssessmentConverter.class)
    @Column(name = "risk_assessment_json", columnDefinition = "TEXT")
    private RiskAssessment riskAssessment;

    @Convert(converter = com.securedeploy.ai.remediation.RemediationSnapshotConverter.class)
    @Column(name = "remediation_snapshot_json", columnDefinition = "TEXT")
    private com.securedeploy.ai.remediation.RemediationSnapshot remediation;

    public com.securedeploy.ai.remediation.RemediationSnapshot getRemediation() { return remediation; }

    @Convert(converter = com.securedeploy.ai.semantic.SemanticSnapshotConverter.class)
    @Column(name = "semantic_snapshot_json", columnDefinition = "TEXT")
    private com.securedeploy.ai.semantic.SemanticSnapshot semanticReview;

    public com.securedeploy.ai.semantic.SemanticSnapshot getSemanticReview() { return semanticReview; }

    public void attachRiskAssessment(RiskAssessment assessment) { this.riskAssessment = assessment; }
    public RiskAssessment getRiskAssessment() { return riskAssessment; }

    public void attachSca(ScaResult result) {
        if (result != null) scaReport = new ReviewScaEntity(this, result);
    }

    public ScaResult getScaResult() {
        return scaReport == null ? null : scaReport.getResult();
    }

    protected ReviewEntity() {
    }

    public ReviewEntity(String projectName, ReviewSourceType sourceType, String repositoryUrl,
                        int scannedFileCount, int vulnerabilityCount, int securityScore,
                        String deploymentStatus) {
        this.projectName = projectName;
        this.sourceType = sourceType;
        this.repositoryUrl = repositoryUrl;
        this.scannedFileCount = scannedFileCount;
        this.vulnerabilityCount = vulnerabilityCount;
        this.securityScore = securityScore;
        this.deploymentStatus = deploymentStatus;
    }

    @PrePersist
    void prePersist() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    public void assignProject(ProjectEntity project) {
        this.project = project;
    }

    public void addVulnerability(VulnerabilityEntity vulnerability) {
        vulnerability.assignReview(this);
        vulnerabilities.add(vulnerability);
    }

    public void addSnippet(ReviewSnippetEntity snippet) {
        snippet.assignReview(this);
        snippets.add(snippet);
    }

    public Long getId() {
        return id;
    }

    public ProjectEntity getProject() {
        return project;
    }

    public String getProjectName() {
        return projectName;
    }

    public ReviewSourceType getSourceType() {
        return sourceType;
    }

    public String getRepositoryUrl() {
        return repositoryUrl;
    }

    public int getScannedFileCount() {
        return scannedFileCount;
    }

    public int getVulnerabilityCount() {
        return vulnerabilityCount;
    }

    public int getSecurityScore() {
        return securityScore;
    }

    public String getDeploymentStatus() {
        return deploymentStatus;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public List<VulnerabilityEntity> getVulnerabilities() {
        return vulnerabilities;
    }

    public List<ReviewSnippetEntity> getSnippets() {
        return snippets;
    }
}
