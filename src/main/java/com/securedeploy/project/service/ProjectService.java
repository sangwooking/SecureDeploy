package com.securedeploy.project.service;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.entity.UserEntity;
import com.securedeploy.persistence.repository.ProjectRepository;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.persistence.repository.UserRepository;
import com.securedeploy.project.dto.ProjectDetailResponse;
import com.securedeploy.project.dto.ProjectResponse;
import com.securedeploy.project.dto.ProjectReviewHistoryResponse;
import com.securedeploy.review.model.ReviewSourceType;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProjectService {

    private final ProjectRepository projectRepository;
    private final ReviewRepository reviewRepository;
    private final UserRepository userRepository;
    private final ProjectLifecycleGuard lifecycle;

    public ProjectService(ProjectRepository projects, ReviewRepository reviews, UserRepository users) {
        this(projects, reviews, users, new ProjectLifecycleGuard());
    }

    @org.springframework.beans.factory.annotation.Autowired
    public ProjectService(ProjectRepository projectRepository, ReviewRepository reviewRepository, UserRepository userRepository,
            ProjectLifecycleGuard lifecycle) {
        this.projectRepository = projectRepository;
        this.reviewRepository = reviewRepository;
        this.userRepository = userRepository;
        this.lifecycle = lifecycle == null ? new ProjectLifecycleGuard() : lifecycle;
    }

    @Transactional
    public ProjectEntity createProject(String name, ReviewSourceType sourceType, String repositoryUrl) {
        return projectRepository.save(new ProjectEntity(name, sourceType, repositoryUrl));
    }

    @Transactional(readOnly = true)
    public List<ProjectResponse> findProjects() {
        return projectRepository.findAllByOrderByUpdatedAtDesc().stream()
                .map(ProjectResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ProjectResponse> findProjectsByUser(Long userId) {
        return projectRepository.findAllByUserIdOrderByUpdatedAtDesc(userId).stream()
                .map(ProjectResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public ProjectDetailResponse findProjectDetail(Long projectId) {
        ProjectEntity project = findProject(projectId);
        return toDetail(project);
    }

    @Transactional(readOnly = true)
    public ProjectDetailResponse findProjectDetail(Long projectId, Long userId) {
        ProjectEntity project = findProjectByIdAndUser(projectId, userId);
        return toDetail(project);
    }

    @Transactional(readOnly = true)
    public List<ProjectReviewHistoryResponse> findProjectReviews(Long projectId) {
        findProject(projectId);
        return reviewRepository.findAllByProjectIdOrderByCreatedAtDesc(projectId).stream()
                .map(ProjectReviewHistoryResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ProjectReviewHistoryResponse> findProjectReviews(Long projectId, Long userId) {
        findProjectByIdAndUser(projectId, userId);
        return reviewRepository.findAllByProjectIdOrderByCreatedAtDesc(projectId).stream()
                .map(ProjectReviewHistoryResponse::from)
                .toList();
    }

    @Transactional
    public ProjectEntity resolveOrCreateProjectForZip(String projectName) {
        try (var lease = lifecycle.zip(null, projectName)) {
            return projectRepository.findFirstByNameAndSourceTypeOrderByUpdatedAtDesc(projectName, ReviewSourceType.ZIP)
                    .orElseGet(() -> projectRepository.save(new ProjectEntity(projectName, ReviewSourceType.ZIP, null)));
        }
    }

    @Transactional
    public ProjectEntity resolveOrCreateProjectForZip(Long userId, String projectName) {
        if (userId == null) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        }
        try (var lease = lifecycle.zip(userId, projectName)) {
            return projectRepository.findFirstByNameAndSourceTypeAndUserIdOrderByUpdatedAtDesc(projectName, ReviewSourceType.ZIP, userId)
                    .orElseGet(() -> createUserProject(userId, projectName, ReviewSourceType.ZIP, null));
        }
    }

    @Transactional
    public ProjectEntity resolveOrCreateProjectForGithub(String repositoryUrl) {
        try (var lease = lifecycle.github(null, repositoryUrl)) {
            return projectRepository.findByRepositoryUrl(repositoryUrl)
                    .orElseGet(() -> projectRepository.save(new ProjectEntity(resolveRepositoryName(repositoryUrl), ReviewSourceType.GITHUB, repositoryUrl)));
        }
    }

    @Transactional
    public ProjectEntity resolveOrCreateProjectForGithub(Long userId, String repositoryUrl) {
        if (userId == null) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        }
        String canonical = com.securedeploy.github.model.GitHubRepositoryUrl.parse(repositoryUrl).canonicalUrl();
        try (var lease = lifecycle.github(userId, canonical)) {
            var matches = projectRepository.findAllByUserIdOrderByUpdatedAtDesc(userId).stream()
                    .filter(p -> p.getSourceType() == ReviewSourceType.GITHUB && p.getGithubRepositoryId() == null && sameRepository(p.getRepositoryUrl(), canonical)).toList();
            if (matches.size() > 1) throw new SecureDeployException(HttpStatus.CONFLICT,
                    "같은 GitHub 저장소로 등록된 프로젝트가 여러 개입니다. 내 프로젝트에서 재검사할 대상을 선택해 주세요.");
            return matches.isEmpty() ? createUserProject(userId, resolveRepositoryName(canonical), ReviewSourceType.GITHUB, canonical) : matches.get(0);
        }
    }

    private boolean sameRepository(String existing, String canonical) {
        try { return com.securedeploy.github.model.GitHubRepositoryUrl.parse(existing).canonicalUrl().equals(canonical); }
        catch (SecureDeployException invalidLegacyUrl) { return false; }
    }

    @Transactional
    public ProjectEntity resolveConnectedGitHubProject(Long userId, Long projectId,
            com.securedeploy.github.model.GitHubSourceSnapshot source) {
        if (userId == null || source.repositoryId() == null || source.installationId() == null)
            throw com.securedeploy.github.app.GitHubAppException.denied();
        try (var lease = lifecycle.connected(userId, source.repositoryId())) {
            ProjectEntity project = projectId == null
                    ? projectRepository.findByUserIdAndGithubRepositoryId(userId, source.repositoryId())
                        .orElseGet(() -> createUserProject(userId, source.repository(), ReviewSourceType.GITHUB, source.canonicalRepositoryUrl()))
                    : findOwnedProjectForRescan(projectId, userId, ReviewSourceType.GITHUB);
            if (projectId != null && !source.repositoryId().equals(project.getGithubRepositoryId()))
                throw com.securedeploy.github.app.GitHubAppException.denied();
            project.bindGitHubRepository(source.repositoryId(), source.installationId(), Boolean.TRUE.equals(source.privateRepository()), source.canonicalRepositoryUrl());
            return projectRepository.save(project);
        }
    }


    @Transactional
    public void deleteProject(Long projectId, Long userId) {
        if (userId == null) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        }
        ProjectEntity project = projectRepository.findById(projectId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "프로젝트를 찾을 수 없습니다."));
        if (project.getUser() == null) {
            throw new SecureDeployException(HttpStatus.FORBIDDEN, "사용자 소유 프로젝트만 삭제할 수 있습니다.");
        }
        if (!project.getUser().getId().equals(userId)) {
            throw new SecureDeployException(HttpStatus.FORBIDDEN, "이 프로젝트를 삭제할 권한이 없습니다.");
        }

        try (var lease = lifecycle.deletion(project)) {
            // Serialize against ReviewPersistenceService before enumerating dependent reviews.
            try {
                project = projectRepository.findForDeletion(projectId)
                        .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "프로젝트를 찾을 수 없습니다."));
            } catch (org.springframework.dao.PessimisticLockingFailureException conflict) {
                throw new SecureDeployException(HttpStatus.CONFLICT, "프로젝트에서 다른 작업이 진행 중입니다. 잠시 후 다시 시도해 주세요.");
            }
            reviewRepository.findAllByProjectIdOrderByCreatedAtDesc(projectId)
                    .forEach(reviewRepository::delete);
            projectRepository.delete(project);
        }
    }

    @Transactional(readOnly = true)
    public ProjectEntity findProject(Long projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "프로젝트를 찾을 수 없습니다."));
    }

    @Transactional(readOnly = true)
    public ProjectEntity findProjectByIdAndUser(Long projectId, Long userId) {
        ProjectEntity project = findProject(projectId);
        com.securedeploy.auth.service.ProjectOwnership.requireOwner(project, userId);
        return project;
    }

    private ProjectDetailResponse toDetail(ProjectEntity project) {
        ProjectReviewHistoryResponse latestReview = reviewRepository.findTopByProjectIdOrderByCreatedAtDescIdDesc(project.getId())
                .map(ProjectReviewHistoryResponse::from)
                .orElse(null);
        return ProjectDetailResponse.from(project, latestReview);
    }

    @Transactional(readOnly = true)
    public ProjectEntity findOwnedProjectForRescan(Long projectId, Long userId, ReviewSourceType type) {
        ProjectEntity project = findProject(projectId);
        if (userId == null || project.getUser() == null || !project.getUser().getId().equals(userId)) {
            throw new SecureDeployException(HttpStatus.FORBIDDEN, "본인 소유 프로젝트만 다시 검사할 수 있습니다.");
        }
        if (project.getSourceType() != type) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "등록된 프로젝트와 같은 분석 방식을 사용해 주세요.");
        }
        return project;
    }

    private ProjectEntity createUserProject(Long userId, String name, ReviewSourceType sourceType, String repositoryUrl) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.UNAUTHORIZED, "사용자 정보를 찾을 수 없습니다. 다시 로그인해 주세요."));
        ProjectEntity project = new ProjectEntity(name, sourceType, repositoryUrl);
        project.assignUser(user);
        return projectRepository.save(project);
    }

    private String resolveRepositoryName(String repositoryUrl) {
        String normalized = repositoryUrl.endsWith(".git") ? repositoryUrl.substring(0, repositoryUrl.length() - 4) : repositoryUrl;
        int slashIndex = normalized.lastIndexOf('/');
        return slashIndex >= 0 ? normalized.substring(slashIndex + 1) : normalized;
    }
}
