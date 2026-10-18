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
import com.securedeploy.project.coverage.CoverageException;
import com.securedeploy.project.coverage.CoverageSummary;
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
    private final com.securedeploy.github.app.PrivateGitHubSourceService privateGitHubSources;
    private final com.securedeploy.analysis.typescript.TypeScriptServerAnalyzer typeScriptAnalyzer;
    private final com.securedeploy.analysis.python.PythonServerAnalyzer pythonAnalyzer;

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
                                com.securedeploy.project.progress.ReviewProgressService progressService,
                                com.securedeploy.github.app.PrivateGitHubSourceService privateGitHubSources,
                                com.securedeploy.analysis.typescript.TypeScriptServerAnalyzer typeScriptAnalyzer,
                                com.securedeploy.analysis.python.PythonServerAnalyzer pythonAnalyzer) {
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
        this.privateGitHubSources = privateGitHubSources;
        this.typeScriptAnalyzer = typeScriptAnalyzer;
        this.pythonAnalyzer = pythonAnalyzer;
    }

    public SecurityReviewResponse reviewUploadedZip(MultipartFile file) {
        return reviewUploadedZip(file, ScanMode.STANDARD);
    }

    public SecurityReviewResponse reviewUploadedZip(MultipartFile file, ScanMode scanMode) {
        UploadedArchive archive = uploadService.saveZip(file);

        try {
            ExtractedProject extractedProject = zipExtractService.extract(archive);
            AnalysisOutcome outcome = reviewProject(extractedProject.projectName(), extractedProject.projectRoot(), scanMode, extractedProject.sourceExclusions());
            ProjectEntity project = projectService.resolveOrCreateProjectForZip(currentUserService.currentUserId(), extractedProject.projectName());
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
            AnalysisOutcome outcome = reviewProject(clonedRepository.repositoryName(), clonedRepository.repositoryRoot(), scanMode, clonedRepository.sourceExclusions());
            ProjectEntity project = projectService.resolveOrCreateProjectForGithub(currentUserService.currentUserId(), clonedRepository.repositoryUrl());
            return saveWithRemediation(project, outcome, ReviewSourceType.GITHUB, clonedRepository.repositoryUrl(), scanMode, clonedRepository.sourceMetadata());
        } finally {
            FileUtils.deleteRecursively(clonedRepository.workspacePath());
        }
    }


    public SecurityReviewResponse reviewUploadedZip(Long projectId, MultipartFile file) {
        return reviewUploadedZip(projectId, file, ScanMode.STANDARD);
    }

    public SecurityReviewResponse reviewUploadedZip(Long projectId, MultipartFile file, ScanMode scanMode) {
        ProjectEntity project = projectService.findOwnedProjectForRescan(projectId, currentUserService.currentUserId(), ReviewSourceType.ZIP);
        UploadedArchive archive = uploadService.saveZip(file);

        try {
            ExtractedProject extractedProject = zipExtractService.extract(archive);
            AnalysisOutcome outcome = reviewProject(extractedProject.projectName(), extractedProject.projectRoot(), scanMode, extractedProject.sourceExclusions());
            return saveWithRemediation(project, outcome, ReviewSourceType.ZIP, null, scanMode);
        } finally {
            FileUtils.deleteRecursively(archive.workspacePath());
        }
    }

    public SecurityReviewResponse reviewGitHubRepository(Long projectId, String repositoryUrl) {
        return reviewGitHubRepository(projectId, repositoryUrl, ScanMode.STANDARD);
    }

    public SecurityReviewResponse reviewGitHubRepository(Long projectId, String repositoryUrl, ScanMode scanMode) {
        ProjectEntity project = projectService.findOwnedProjectForRescan(projectId, currentUserService.currentUserId(), ReviewSourceType.GITHUB);
        if (project.getGithubRepositoryId() != null) {
            return reviewConnectedGitHub(projectId, project.getGithubInstallationId(), project.getGithubRepositoryId(), scanMode);
        }
        String requested = gitHubRepositoryService.validateAndNormalizeUrl(repositoryUrl).replaceFirst("\\.git$", "");
        String registered = gitHubRepositoryService.validateAndNormalizeUrl(project.getRepositoryUrl()).replaceFirst("\\.git$", "");
        if (!requested.equalsIgnoreCase(registered)) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "등록된 GitHub 저장소만 다시 검사할 수 있습니다.");
        }
        ClonedRepository clonedRepository = gitHubRepositoryService.clonePublicRepository(project.getRepositoryUrl());

        try {
            AnalysisOutcome outcome = reviewProject(clonedRepository.repositoryName(), clonedRepository.repositoryRoot(), scanMode, clonedRepository.sourceExclusions());
            return saveWithRemediation(project, outcome, ReviewSourceType.GITHUB, clonedRepository.repositoryUrl(), scanMode, clonedRepository.sourceMetadata());
        } finally {
            FileUtils.deleteRecursively(clonedRepository.workspacePath());
        }
    }

    public List<ReviewHistoryResponse> findReviewHistories() {
        return reviewPersistenceService.findReviewHistories(currentUserService.currentUserId());
    }

    public SecurityReviewResponse reviewConnectedGitHub(Long projectId, long installationId, long repositoryId, ScanMode scanMode) {
        Long userId = currentUserService.currentUserId();
        if (projectId != null) {
            var project = projectService.findOwnedProjectForRescan(projectId, userId, ReviewSourceType.GITHUB);
            if (!Long.valueOf(repositoryId).equals(project.getGithubRepositoryId()))
                throw com.securedeploy.github.app.GitHubAppException.denied();
        }
        ClonedRepository clone = privateGitHubSources.collect(userId, installationId, repositoryId);
        try {
            AnalysisOutcome outcome = reviewProject(clone.repositoryName(), clone.repositoryRoot(), scanMode, clone.sourceExclusions());
            ProjectEntity project = projectService.resolveConnectedGitHubProject(userId, projectId, clone.sourceMetadata());
            return saveWithRemediation(project, outcome, ReviewSourceType.GITHUB, clone.repositoryUrl(), scanMode, clone.sourceMetadata());
        } finally { FileUtils.deleteRecursively(clone.workspacePath()); }
    }

    private SecurityReviewResponse saveWithRemediation(ProjectEntity project, AnalysisOutcome outcome,
                                                       ReviewSourceType type, String repositoryUrl, ScanMode scanMode) {
        return saveWithRemediation(project, outcome, type, repositoryUrl, scanMode, null);
    }

    private SecurityReviewResponse saveWithRemediation(ProjectEntity project, AnalysisOutcome outcome,
            ReviewSourceType type, String repositoryUrl, ScanMode scanMode,
            com.securedeploy.github.model.GitHubSourceSnapshot source) {
        var response = source == null ? outcome.response() : outcome.response().withSourceMetadata(source.analyzedNow());
        var saved = reviewPersistenceService.saveReview(project, response, type, repositoryUrl,
                outcome.snippetGroup(), outcome.intelligence(), scanMode, outcome.comparisonContext());
        var guided = remediationService.complete(saved, outcome.snippetGroup(), scanMode == ScanMode.AI_ENHANCED);
        return progressService.complete(semanticService.complete(guided, scanMode, outcome.slices()));
    }

    public SecurityReviewResponse findReviewDetail(Long reviewId) {
        return reviewPersistenceService.findReviewDetail(reviewId, currentUserService.currentUserId());
    }

    private AnalysisOutcome reviewProject(String projectName, Path projectRoot, ScanMode scanMode,
            com.securedeploy.project.coverage.CoverageLedger sourceExclusions) {
        ProjectStructure projectStructure;
        try { projectStructure = projectScanner.scan(projectRoot); }
        catch (CoverageException failure) {
            throw new CoverageException(failure.getStatus(), failure.getMessage(), CoverageSummary.failure(failure.coverage(), sourceExclusions, "FILE_COLLECTION"));
        }
        if (projectStructure.analysisFiles().isEmpty()) {
            throw new CoverageException(HttpStatus.BAD_REQUEST, "분석 가능한 파일을 찾지 못했습니다. 지원하는 코드 또는 설정 파일이 포함되어 있는지 확인해 주세요. 미지원 영역을 안전으로 판단하지 않습니다.", CoverageSummary.failure(projectStructure.coverage(), sourceExclusions, "FILE_COLLECTION"));
        }
        List<RuleMatch> rawMatches;
        try { rawMatches = ruleEngine.execute(new RuleExecutionContext(projectStructure)); }
        catch (RuntimeException failure) {
            throw new CoverageException(HttpStatus.INTERNAL_SERVER_ERROR, "코드 패턴 검사를 완료하지 못했습니다.", CoverageSummary.failure(projectStructure.coverage(), sourceExclusions, "RULE_ENGINE"));
        }
        List<RuleMatch> matches;
        try { matches = falsePositiveAnalyzer.analyze(projectStructure, rawMatches); }
        catch (RuntimeException failure) {
            throw new CoverageException(HttpStatus.INTERNAL_SERVER_ERROR, "탐지 신뢰도 검토를 완료하지 못했습니다.", CoverageSummary.failure(projectStructure.coverage(), sourceExclusions, "FALSE_POSITIVE"));
        }
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
        var intelligence = threatIntelligenceService.enrich(sca);
        var pythonAnalysis = pythonAnalyzer.analyze(projectStructure);
        var serverAnalysis = typeScriptAnalyzer.analyze(projectStructure).withPythonAnalysis(pythonAnalysis);
        var coverage = com.securedeploy.project.coverage.CoverageSummary.complete(projectStructure.coverage(), sourceExclusions, sca, intelligence);
        coverage = serverAnalysis.attachCoverage(coverage);
        coverage = pythonAnalysis.attachCoverage(coverage);
        coverage = coverage.withInspectionScope(com.securedeploy.project.coverage.InspectionScope.collect(coverage, projectStructure.analysisFiles()));
        return new AnalysisOutcome(response.withSca(sca).withServerAnalysis(serverAnalysis).withCoverage(coverage), snippetGroup, intelligence, slices,
                comparisonCollector.collect(projectStructure));
    }

    private record AnalysisOutcome(SecurityReviewResponse response, SnippetGroup snippetGroup, ThreatIntelligenceSnapshot intelligence,
                                   SecuritySliceCollector.Collection slices,
                                   com.securedeploy.project.progress.ComparisonContext comparisonContext) {
    }
}
