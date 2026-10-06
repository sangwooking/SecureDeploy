package com.securedeploy.persistence;

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
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class LongTextPersistenceTest {

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
    void storesLongVulnerabilityTextAndSnippetContent() {
        String longMessage = "message-" + "m".repeat(1_500);
        String longRecommendation = "recommendation-" + "r".repeat(2_000);
        String longEvidence = "evidence-" + "e".repeat(2_500);
        String longStatusComment = "comment-" + "c".repeat(1_800);
        String longSnippet = "snippet-" + "s".repeat(3_000);

        UserEntity user = userRepository.save(new UserEntity("long-text@test.com", "hash", "Long Text"));
        ProjectEntity project = new ProjectEntity("long-text-project", ReviewSourceType.GITHUB, "https://github.com/example/long-text.git");
        project.assignUser(user);
        ProjectEntity savedProject = projectRepository.save(project);

        ReviewEntity review = new ReviewEntity("long-text-project", ReviewSourceType.GITHUB, savedProject.getRepositoryUrl(), 42, 1, 70, "주의 필요");
        review.assignProject(savedProject);
        VulnerabilityEntity vulnerability = new VulnerabilityEntity(
                "LONG_TEXT_RULE",
                RuleCategory.CONFIGURATION,
                Severity.HIGH,
                "src/main/resources/application.yml",
                1,
                longMessage,
                longRecommendation,
                longEvidence
        );
        vulnerability.updateStatus(com.securedeploy.vulnerability.model.VulnerabilityStatus.IN_PROGRESS, longStatusComment);
        review.addVulnerability(vulnerability);
        review.addSnippet(new ReviewSnippetEntity(SnippetType.CONFIG, "application.yml", longSnippet));

        ReviewEntity savedReview = reviewRepository.saveAndFlush(review);
        entityManager.clear();

        VulnerabilityEntity savedVulnerability = vulnerabilityRepository.findAllByReviewProjectId(savedProject.getId()).get(0);
        String savedSnippet = entityManager.createQuery("select s.content from ReviewSnippetEntity s where s.review.id = :reviewId", String.class)
                .setParameter("reviewId", savedReview.getId())
                .getSingleResult();

        assertThat(savedVulnerability.getMessage()).hasSize(longMessage.length());
        assertThat(savedVulnerability.getRecommendation()).hasSize(longRecommendation.length());
        assertThat(savedVulnerability.getEvidence()).hasSize(longEvidence.length());
        assertThat(savedVulnerability.getStatusComment()).hasSize(longStatusComment.length());
        assertThat(savedSnippet).hasSize(longSnippet.length());
    }
}
