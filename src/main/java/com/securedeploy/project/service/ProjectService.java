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

    public ProjectService(ProjectRepository projectRepository, ReviewRepository reviewRepository, UserRepository userRepository) {
        this.projectRepository = projectRepository;
        this.reviewRepository = reviewRepository;
        this.userRepository = userRepository;
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
        return projectRepository.findFirstByNameAndSourceTypeOrderByUpdatedAtDesc(projectName, ReviewSourceType.ZIP)
                .orElseGet(() -> projectRepository.save(new ProjectEntity(projectName, ReviewSourceType.ZIP, null)));
    }

    @Transactional
    public ProjectEntity resolveOrCreateProjectForZip(Long userId, String projectName) {
        if (userId == null) {
            return resolveOrCreateProjectForZip(projectName);
        }
        return projectRepository.findFirstByNameAndSourceTypeAndUserIdOrderByUpdatedAtDesc(projectName, ReviewSourceType.ZIP, userId)
                .orElseGet(() -> createUserProject(userId, projectName, ReviewSourceType.ZIP, null));
    }

    @Transactional
    public ProjectEntity resolveOrCreateProjectForGithub(String repositoryUrl) {
        return projectRepository.findByRepositoryUrl(repositoryUrl)
                .orElseGet(() -> projectRepository.save(new ProjectEntity(resolveRepositoryName(repositoryUrl), ReviewSourceType.GITHUB, repositoryUrl)));
    }

    @Transactional
    public ProjectEntity resolveOrCreateProjectForGithub(Long userId, String repositoryUrl) {
        if (userId == null) {
            return resolveOrCreateProjectForGithub(repositoryUrl);
        }
        return projectRepository.findByRepositoryUrlAndUserId(repositoryUrl, userId)
                .orElseGet(() -> createUserProject(userId, resolveRepositoryName(repositoryUrl), ReviewSourceType.GITHUB, repositoryUrl));
    }

    @Transactional(readOnly = true)
    public ProjectEntity findProject(Long projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "프로젝트를 찾을 수 없습니다."));
    }

    @Transactional(readOnly = true)
    public ProjectEntity findProjectByIdAndUser(Long projectId, Long userId) {
        ProjectEntity project = findProject(projectId);
        if (project.getUser() == null) {
            return project;
        }
        if (project.getUser().getId().equals(userId)) {
            return project;
        }
        throw new SecureDeployException(HttpStatus.FORBIDDEN, "이 프로젝트에 접근할 권한이 없습니다.");
    }

    private ProjectDetailResponse toDetail(ProjectEntity project) {
        ProjectReviewHistoryResponse latestReview = reviewRepository.findTopByProjectIdOrderByCreatedAtDesc(project.getId())
                .map(ProjectReviewHistoryResponse::from)
                .orElse(null);
        return ProjectDetailResponse.from(project, latestReview);
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
