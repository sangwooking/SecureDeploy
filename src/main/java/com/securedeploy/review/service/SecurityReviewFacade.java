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
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.upload.model.ExtractedProject;
import com.securedeploy.upload.model.UploadedArchive;
import com.securedeploy.upload.service.UploadService;
import com.securedeploy.upload.service.ZipExtractService;
import java.nio.file.Path;
import org.springframework.http.HttpStatus;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class SecurityReviewFacade {

    private final UploadService uploadService;
    private final ZipExtractService zipExtractService;
    private final GitHubRepositoryService gitHubRepositoryService;
    private final ProjectScanner projectScanner;
    private final VulnerabilityRuleEngine ruleEngine;
    private final SecurityReviewService securityReviewService;
    private final ReviewPersistenceService reviewPersistenceService;
    private final SnippetCollector snippetCollector;
    private final ProjectService projectService;
    private final CurrentUserService currentUserService;

    public SecurityReviewFacade(UploadService uploadService, ZipExtractService zipExtractService,
                                GitHubRepositoryService gitHubRepositoryService,
                                ProjectScanner projectScanner, VulnerabilityRuleEngine ruleEngine,
                                SecurityReviewService securityReviewService,
                                ReviewPersistenceService reviewPersistenceService,
                                SnippetCollector snippetCollector,
                                ProjectService projectService,
                                CurrentUserService currentUserService) {
        this.uploadService = uploadService;
        this.zipExtractService = zipExtractService;
        this.gitHubRepositoryService = gitHubRepositoryService;
        this.projectScanner = projectScanner;
        this.ruleEngine = ruleEngine;
        this.securityReviewService = securityReviewService;
        this.reviewPersistenceService = reviewPersistenceService;
        this.snippetCollector = snippetCollector;
        this.projectService = projectService;
        this.currentUserService = currentUserService;
    }

    public SecurityReviewResponse reviewUploadedZip(MultipartFile file) {
        UploadedArchive archive = uploadService.saveZip(file);

        try {
            ExtractedProject extractedProject = zipExtractService.extract(archive);
            AnalysisOutcome outcome = reviewProject(extractedProject.projectName(), extractedProject.projectRoot());
            ProjectEntity project = projectService.resolveOrCreateProjectForZip(currentUserService.currentUserIdOrNull(), extractedProject.projectName());
            return reviewPersistenceService.saveReview(project, outcome.response(), ReviewSourceType.ZIP, null, outcome.snippetGroup());
        } finally {
            FileUtils.deleteRecursively(archive.workspacePath());
        }
    }

    public SecurityReviewResponse reviewGitHubRepository(String repositoryUrl) {
        ClonedRepository clonedRepository = gitHubRepositoryService.clonePublicRepository(repositoryUrl);

        try {
            AnalysisOutcome outcome = reviewProject(clonedRepository.repositoryName(), clonedRepository.repositoryRoot());
            ProjectEntity project = projectService.resolveOrCreateProjectForGithub(currentUserService.currentUserIdOrNull(), clonedRepository.repositoryUrl());
            return reviewPersistenceService.saveReview(project, outcome.response(), ReviewSourceType.GITHUB, clonedRepository.repositoryUrl(), outcome.snippetGroup());
        } finally {
            FileUtils.deleteRecursively(clonedRepository.workspacePath());
        }
    }


    public SecurityReviewResponse reviewUploadedZip(Long projectId, MultipartFile file) {
        ProjectEntity project = projectService.findProjectByIdAndUser(projectId, currentUserService.currentUserIdOrNull());
        UploadedArchive archive = uploadService.saveZip(file);

        try {
            ExtractedProject extractedProject = zipExtractService.extract(archive);
            AnalysisOutcome outcome = reviewProject(extractedProject.projectName(), extractedProject.projectRoot());
            return reviewPersistenceService.saveReview(project, outcome.response(), ReviewSourceType.ZIP, null, outcome.snippetGroup());
        } finally {
            FileUtils.deleteRecursively(archive.workspacePath());
        }
    }

    public SecurityReviewResponse reviewGitHubRepository(Long projectId, String repositoryUrl) {
        ProjectEntity project = projectService.findProjectByIdAndUser(projectId, currentUserService.currentUserIdOrNull());
        ClonedRepository clonedRepository = gitHubRepositoryService.clonePublicRepository(repositoryUrl);

        try {
            AnalysisOutcome outcome = reviewProject(clonedRepository.repositoryName(), clonedRepository.repositoryRoot());
            return reviewPersistenceService.saveReview(project, outcome.response(), ReviewSourceType.GITHUB, clonedRepository.repositoryUrl(), outcome.snippetGroup());
        } finally {
            FileUtils.deleteRecursively(clonedRepository.workspacePath());
        }
    }

    public List<ReviewHistoryResponse> findReviewHistories() {
        return reviewPersistenceService.findReviewHistories(currentUserService.currentUserIdOrNull());
    }

    public SecurityReviewResponse findReviewDetail(Long reviewId) {
        return reviewPersistenceService.findReviewDetail(reviewId, currentUserService.currentUserIdOrNull());
    }

    private AnalysisOutcome reviewProject(String projectName, Path projectRoot) {
        ProjectStructure projectStructure = projectScanner.scan(projectRoot);
        if (projectStructure.analysisFiles().isEmpty()) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "분석 가능한 파일을 찾지 못했습니다. Spring Boot 또는 React/Vite 프로젝트의 .java, .js, .ts, .tsx, 설정 파일, package.json, pom.xml, build.gradle, Dockerfile 또는 배포 설정 파일이 포함되어 있는지 확인해 주세요.");
        }
        List<RuleMatch> matches = ruleEngine.execute(new RuleExecutionContext(projectStructure));
        SnippetGroup snippetGroup = snippetCollector.collect(projectStructure);

        SecurityReviewResponse response = securityReviewService.createResponse(
                projectName,
                projectStructure.analysisFiles().size(),
                matches
        );
        return new AnalysisOutcome(response, snippetGroup);
    }

    private record AnalysisOutcome(SecurityReviewResponse response, SnippetGroup snippetGroup) {
    }
}
