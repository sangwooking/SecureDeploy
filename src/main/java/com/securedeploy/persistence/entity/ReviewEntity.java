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
