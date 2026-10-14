package com.securedeploy.review.service;

import com.securedeploy.ai.context.SnippetCollector;
import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.ai.context.SnippetGroup;
import com.securedeploy.github.model.ClonedRepository;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.github.service.GitHubRepositoryService;
import com.securedeploy.global.util.FileUtils;
import com.securedeploy.persistence.service.ReviewPersistenceService;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.project.service.ProjectScanner;
import com.securedeploy.project.service.ProjectService;
import com.securedeploy.review.dto.ReviewHistoryResponse;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.rule.engine.RuleExecutionContext;
import com.securedeploy.rule.engine.VulnerabilityRuleEngine;
import com.securedeploy.rule.filter.FalsePositiveAnalyzer;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.sca.service.ScaService;
import com.securedeploy.threatintel.service.ThreatIntelligenceService;
import com.securedeploy.threatintel.model.ThreatIntelligenceSnapshot;
import com.securedeploy.upload.model.ExtractedProject;
import com.securedeploy.upload.model.UploadedArchive;
import com.securedeploy.upload.service.UploadService;
import com.securedeploy.upload.service.ZipExtractService;
import java.nio.file.Path;
import org.springframework.http.HttpStatus;
import java.util.List;
import com.securedeploy.review.model.ScanMode;
import com.securedeploy.ai.semantic.SecuritySliceCollector;
import com.securedeploy.ai.semantic.SemanticSnapshotService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class SecurityReviewFacade {

    private final UploadService uploadService;
    private final ZipExtractService zipExtractService;
    private final GitHubRepositoryService gitHubRepositoryService;
    private final ProjectScanner projectScanner;
    private final VulnerabilityRuleEngine ruleEngine;
    private final FalsePositiveAnalyzer falsePositiveAnalyzer;
    private final SecurityReviewService securityReviewService;
    private final ReviewPersistenceService reviewPersistenceService;
    private final SnippetCollector snippetCollector;
    private final ProjectService projectService;
    private final CurrentUserService currentUserService;
    private final ScaService scaService;
    private final ThreatIntelligenceService threatIntelligenceService;
    private final com.securedeploy.ai.remediation.RemediationSnapshotService remediationService;
    private final SecuritySliceCollector sliceCollector;
    private final SemanticSnapshotService semanticService;
    private final com.securedeploy.project.progress.ComparisonContextCollector comparisonCollector;
    private final com.securedeploy.project.progress.ReviewProgressService progressService;

    public SecurityReviewFacade(UploadService uploadService, ZipExtractService zipExtractService,
                                GitHubRepositoryService gitHubRepositoryService,
                                ProjectScanner projectScanner, VulnerabilityRuleEngine ruleEngine,
                                FalsePositiveAnalyzer falsePositiveAnalyzer,
                                SecurityReviewService securityReviewService,
                                ReviewPersistenceService reviewPersistenceService,
                                SnippetCollector snippetCollector,
                                ProjectService projectService,
                                CurrentUserService currentUserService, ScaService scaService,
                                ThreatIntelligenceService threatIntelligenceService,
                                com.securedeploy.ai.remediation.RemediationSnapshotService remediationService,
                                SecuritySliceCollector sliceCollector, SemanticSnapshotService semanticService,
                                com.securedeploy.project.progress.ComparisonContextCollector comparisonCollector,
                                com.securedeploy.project.progress.ReviewProgressService progressService) {
        this.uploadService = uploadService;
        this.zipExtractService = zipExtractService;
        this.gitHubRepositoryService = gitHubRepositoryService;
        this.projectScanner = projectScanner;
        this.ruleEngine = ruleEngine;
        this.falsePositiveAnalyzer = falsePositiveAnalyzer;
        this.securityReviewService = securityReviewService;
        this.reviewPersistenceService = reviewPersistenceService;
        this.snippetCollector = snippetCollector;
        this.projectService = projectService;
        this.currentUserService = currentUserService;
        this.scaService = scaService;
        this.threatIntelligenceService = threatIntelligenceService;
        this.remediationService = remediationService;
        this.sliceCollector = sliceCollector;
        this.semanticService = semanticService;
        this.comparisonCollector = comparisonCollector;
        this.progressService = progressService;
    }

    public SecurityReviewResponse reviewUploadedZip(MultipartFile file) {
        return reviewUploadedZip(file, ScanMode.STANDARD);
    }

    public SecurityReviewResponse reviewUploadedZip(MultipartFile file, ScanMode scanMode) {
        UploadedArchive archive = uploadService.saveZip(file);

        try {
            ExtractedProject extractedProject = zipExtractService.extract(archive);
            AnalysisOutcome outcome = reviewProject(extractedProject.projectName(), extractedProject.projectRoot(), scanMode);
            ProjectEntity project = projectService.resolveOrCreateProjectForZip(currentUserService.currentUserIdOrNull(), extractedProject.projectName());
            return saveWithRemediation(project, outcome, ReviewSourceType.ZIP, null, scanMode);
        } finally {
            FileUtils.deleteRecursively(archive.workspacePath());
        }
    }

    public SecurityReviewResponse reviewGitHubRepository(String repositoryUrl) {
        return reviewGitHubRepository(repositoryUrl, ScanMode.STANDARD);
    }

    public SecurityReviewResponse reviewGitHubRepository(String repositoryUrl, ScanMode scanMode) {
        ClonedRepository clonedRepository = gitHubRepositoryService.clonePublicRepository(repositoryUrl);

        try {
            AnalysisOutcome outcome = reviewProject(clonedRepository.repositoryName(), clonedRepository.repositoryRoot(), scanMode);
            ProjectEntity project = projectService.resolveOrCreateProjectForGithub(currentUserService.currentUserIdOrNull(), clonedRepository.repositoryUrl());
            return saveWithRemediation(project, outcome, ReviewSourceType.GITHUB, clonedRepository.repositoryUrl(), scanMode);
        } finally {
            FileUtils.deleteRecursively(clonedRepository.workspacePath());
        }
    }


    public SecurityReviewResponse reviewUploadedZip(Long projectId, MultipartFile file) {
        return reviewUploadedZip(projectId, file, ScanMode.STANDARD);
    }

    public SecurityReviewResponse reviewUploadedZip(Long projectId, MultipartFile file, ScanMode scanMode) {
        ProjectEntity project = projectService.findOwnedProjectForRescan(projectId, currentUserService.currentUserIdOrNull(), ReviewSourceType.ZIP);
        UploadedArchive archive = uploadService.saveZip(file);

        try {
            ExtractedProject extractedProject = zipExtractService.extract(archive);
            AnalysisOutcome outcome = reviewProject(extractedProject.projectName(), extractedProject.projectRoot(), scanMode);
            return saveWithRemediation(project, outcome, ReviewSourceType.ZIP, null, scanMode);
        } finally {
            FileUtils.deleteRecursively(archive.workspacePath());
        }
    }

    public SecurityReviewResponse reviewGitHubRepository(Long projectId, String repositoryUrl) {
        return reviewGitHubRepository(projectId, repositoryUrl, ScanMode.STANDARD);
    }

    public SecurityReviewResponse reviewGitHubRepository(Long projectId, String repositoryUrl, ScanMode scanMode) {
        ProjectEntity project = projectService.findOwnedProjectForRescan(projectId, currentUserService.currentUserIdOrNull(), ReviewSourceType.GITHUB);
        String requested = gitHubRepositoryService.validateAndNormalizeUrl(repositoryUrl).replaceFirst("\\.git$", "");
        String registered = gitHubRepositoryService.validateAndNormalizeUrl(project.getRepositoryUrl()).replaceFirst("\\.git$", "");
        if (!requested.equalsIgnoreCase(registered)) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "등록된 GitHub 저장소만 다시 검사할 수 있습니다.");
        }
        ClonedRepository clonedRepository = gitHubRepositoryService.clonePublicRepository(repositoryUrl);

        try {
            AnalysisOutcome outcome = reviewProject(clonedRepository.repositoryName(), clonedRepository.repositoryRoot(), scanMode);
            return saveWithRemediation(project, outcome, ReviewSourceType.GITHUB, clonedRepository.repositoryUrl(), scanMode);
        } finally {
            FileUtils.deleteRecursively(clonedRepository.workspacePath());
        }
    }

    public List<ReviewHistoryResponse> findReviewHistories() {
        return reviewPersistenceService.findReviewHistories(currentUserService.currentUserIdOrNull());
    }

    private SecurityReviewResponse saveWithRemediation(ProjectEntity project, AnalysisOutcome outcome,
                                                       ReviewSourceType type, String repositoryUrl, ScanMode scanMode) {
        var saved = reviewPersistenceService.saveReview(project, outcome.response(), type, repositoryUrl,
                outcome.snippetGroup(), outcome.intelligence(), scanMode, outcome.comparisonContext());
        var guided = remediationService.complete(saved, outcome.snippetGroup(), scanMode == ScanMode.AI_ENHANCED);
        return progressService.complete(semanticService.complete(guided, scanMode, outcome.slices()));
    }

    public SecurityReviewResponse findReviewDetail(Long reviewId) {
        return reviewPersistenceService.findReviewDetail(reviewId, currentUserService.currentUserIdOrNull());
    }

    private AnalysisOutcome reviewProject(String projectName, Path projectRoot, ScanMode scanMode) {
        ProjectStructure projectStructure = projectScanner.scan(projectRoot);
        if (projectStructure.analysisFiles().isEmpty()) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "분석 가능한 파일을 찾지 못했습니다. Spring Boot 또는 React/Vite 프로젝트의 .java, .js, .ts, .tsx, 설정 파일, package.json, pom.xml, build.gradle, Dockerfile 또는 배포 설정 파일이 포함되어 있는지 확인해 주세요.");
        }
        List<RuleMatch> rawMatches = ruleEngine.execute(new RuleExecutionContext(projectStructure));
        List<RuleMatch> matches = falsePositiveAnalyzer.analyze(projectStructure, rawMatches);
        SnippetGroup snippetGroup = snippetCollector.collect(projectStructure);

        SecurityReviewResponse response = securityReviewService.createResponse(
                projectName,
                projectStructure.analysisFiles().size(),
                matches
        );
        var sca = scaService.analyze(projectStructure);
        SecuritySliceCollector.Collection slices = SecuritySliceCollector.Collection.empty();
        if (scanMode == ScanMode.AI_ENHANCED) {
            try { slices = sliceCollector.collect(projectStructure); }
            catch (RuntimeException | LinkageError unavailable) {
                slices = new SecuritySliceCollector.Collection(List.of(), 0, List.of("Java slice indexing unavailable."), false);
            }
        }
        return new AnalysisOutcome(response.withSca(sca), snippetGroup, threatIntelligenceService.enrich(sca), slices,
                comparisonCollector.collect(projectStructure));
    }

    private record AnalysisOutcome(SecurityReviewResponse response, SnippetGroup snippetGroup, ThreatIntelligenceSnapshot intelligence,
                                   SecuritySliceCollector.Collection slices,
                                   com.securedeploy.project.progress.ComparisonContext comparisonContext) {
    }
}
