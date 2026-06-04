package com.securedeploy.project;

import static org.assertj.core.api.Assertions.assertThat;

import com.securedeploy.ai.context.SnippetType;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.entity.ReviewSnippetEntity;
import com.securedeploy.persistence.entity.UserEntity;
import com.securedeploy.persistence.entity.VulnerabilityEntity;
import com.securedeploy.persistence.repository.ProjectRepository;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.persistence.repository.UserRepository;
import com.securedeploy.persistence.repository.VulnerabilityRepository;
import com.securedeploy.project.comparison.ReviewComparisonService;
import com.securedeploy.project.dto.ProjectSecurityDashboardResponse;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import com.securedeploy.project.service.ProjectDashboardService;
import com.securedeploy.project.service.ProjectService;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.review.service.ReviewDeleteService;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ProjectAndReviewDeleteServiceTest {

    @Autowired
    private ReviewDeleteService reviewDeleteService;

    @Autowired
    private ProjectService projectService;

    @Autowired
    private ProjectDashboardService projectDashboardService;

    @Autowired
    private ReviewComparisonService reviewComparisonService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private ReviewRepository reviewRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private EntityManager entityManager;

    @BeforeEach
    void cleanUp() {
        reviewRepository.deleteAll();
        projectRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void deletingLatestReviewKeepsProjectAndDashboardUsesPreviousReview() {
        UserEntity user = userRepository.save(new UserEntity("delete-dashboard@test.com", "hash", "Delete User"));
        ProjectEntity project = saveProject(user, "dashboard-project");
        ReviewEntity previous = saveReview(project, 70, 3, "주의 필요", "PREVIOUS_RULE");
        ReviewEntity latest = saveReview(project, 95, 1, "배포 가능", "LATEST_RULE");

        reviewDeleteService.deleteReview(latest.getId(), user.getId());

        assertThat(projectRepository.existsById(project.getId())).isTrue();
        assertThat(reviewRepository.findById(latest.getId())).isEmpty();
        ProjectSecurityDashboardResponse dashboard = projectDashboardService.getDashboard(project.getId(), user.getId());
        assertThat(dashboard.latestReviewId()).isEqualTo(previous.getId());
        assertThat(dashboard.latestSecurityScore()).isEqualTo(70);
        assertThat(dashboard.scoreHistory()).hasSize(1);

        ReviewComparisonResponse comparison = reviewComparisonService.compareLatest(project.getId());
        assertThat(comparison.latestReviewId()).isNull();
        assertThat(comparison.message()).contains("최소 2개");
    }

    @Test
    void deletingOneOfThreeReviewsRecalculatesLatestComparisonFromRemainingReviews() {
        UserEntity user = userRepository.save(new UserEntity("delete-compare@test.com", "hash", "Compare User"));
        ProjectEntity project = saveProject(user, "compare-project");
        ReviewEntity oldest = saveReview(project, 40, 9, "배포 비권장", "OLDEST_RULE");
        ReviewEntity middle = saveReview(project, 70, 4, "주의 필요", "MIDDLE_RULE");
        ReviewEntity latest = saveReview(project, 90, 1, "배포 가능", "LATEST_RULE");

        reviewDeleteService.deleteReview(middle.getId(), user.getId());

        ReviewComparisonResponse comparison = reviewComparisonService.compareLatest(project.getId());
        assertThat(comparison.latestReviewId()).isEqualTo(latest.getId());
        assertThat(comparison.previousReviewId()).isEqualTo(oldest.getId());
        assertThat(comparison.scoreDiff()).isEqualTo(50);
        assertThat(comparison.vulnerabilityCountDiff()).isEqualTo(-8);
    }

    @Test
    void deletingProjectDeletesReviewsVulnerabilitiesAndSnippets() {
        UserEntity user = userRepository.save(new UserEntity("delete-project@test.com", "hash", "Project User"));
        ProjectEntity project = saveProject(user, "delete-project");
        saveReview(project, 60, 2, "주의 필요", "FIRST_RULE");
        saveReview(project, 85, 1, "배포 가능", "SECOND_RULE");

        assertThat(reviewRepository.findAllByProjectIdOrderByCreatedAtDesc(project.getId())).hasSize(2);
        assertThat(vulnerabilityRepository.findAllByReviewProjectId(project.getId())).hasSize(2);
        assertThat(countSnippets()).isEqualTo(2);

        projectService.deleteProject(project.getId(), user.getId());

        assertThat(projectRepository.findById(project.getId())).isEmpty();
        assertThat(reviewRepository.findAllByProjectIdOrderByCreatedAtDesc(project.getId())).isEmpty();
        assertThat(vulnerabilityRepository.findAll()).isEmpty();
        assertThat(countSnippets()).isZero();
    }

    private ProjectEntity saveProject(UserEntity user, String name) {
        ProjectEntity project = new ProjectEntity(name, ReviewSourceType.ZIP, null);
        project.assignUser(user);
        return projectRepository.save(project);
    }

    private ReviewEntity saveReview(ProjectEntity project, int score, int vulnerabilityCount, String deploymentStatus, String ruleId) {
        ReviewEntity review = new ReviewEntity(
                project.getName(),
                ReviewSourceType.ZIP,
                null,
                10,
                vulnerabilityCount,
                score,
                deploymentStatus
        );
        review.assignProject(project);
        review.addVulnerability(new VulnerabilityEntity(
                ruleId,
                RuleCategory.CONFIGURATION,
                Severity.HIGH,
                "application.yml",
                1,
                "test vulnerability",
                "fix it",
                "evidence"
        ));
        review.addSnippet(new ReviewSnippetEntity(SnippetType.CONFIG, "application.yml", "debug=true"));
        ReviewEntity saved = reviewRepository.saveAndFlush(review);
        entityManager.clear();
        sleepForCreatedAtOrdering();
        return saved;
    }

    private long countSnippets() {
        return entityManager.createQuery("select count(s) from ReviewSnippetEntity s", Long.class)
                .getSingleResult();
    }

    private void sleepForCreatedAtOrdering() {
        try {
            Thread.sleep(5);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }
}
