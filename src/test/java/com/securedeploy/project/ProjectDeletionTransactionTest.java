package com.securedeploy.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

import com.securedeploy.ai.context.SnippetType;
import com.securedeploy.ai.remediation.RemediationSnapshot;
import com.securedeploy.ai.semantic.SemanticSnapshot;
import com.securedeploy.github.app.GitHubConnectionEntity;
import com.securedeploy.github.app.GitHubConnectionRepository;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.persistence.repository.*;
import com.securedeploy.project.service.ProjectService;
import com.securedeploy.project.service.ProjectLifecycleGuard;
import com.securedeploy.project.progress.ReviewProgressSnapshot;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.review.model.ScanMode;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.sca.model.ScaResult;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@DataJpaTest(properties = "spring.jpa.show-sql=false")
@Import({ProjectService.class, ProjectLifecycleGuard.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class ProjectDeletionTransactionTest {
    @Autowired ProjectService service;
    @Autowired ProjectLifecycleGuard lifecycle;
    @SpyBean ProjectRepository projects;
    @SpyBean ReviewRepository reviews;
    @Autowired UserRepository users;
    @Autowired GitHubConnectionRepository connections;
    @Autowired EntityManager em;
    @Autowired PlatformTransactionManager transactions;
    private TransactionTemplate tx;
    private UserEntity owner;
    private ProjectEntity target;

    @BeforeEach
    void setup() {
        tx = new TransactionTemplate(transactions);
        connections.deleteAll();
        reviews.deleteAll();
        projects.deleteAll();
        users.deleteAll();
        owner = users.save(new UserEntity("deletion@test.com", "hash", "Owner"));
        target = project(owner, "target");
    }

    @AfterEach
    void resetSpies() { reset(projects, reviews); }

    @Test
    void deletesOnlyTargetGraphAndPreservesAccountsConnectionsAndOtherProjects() {
        var other = users.save(new UserEntity("other@test.com", "hash", "Other"));
        var sibling = project(owner, "sibling");
        var foreign = project(other, "foreign");
        long first = review(target), second = review(target);
        long siblingReview = review(sibling), foreignReview = review(foreign);
        connections.save(new GitHubConnectionEntity(owner, 42, "owner", "ciphertext", Instant.now().plusSeconds(3600)));
        connections.save(new GitHubConnectionEntity(other, 43, "other", "other-ciphertext", Instant.now().plusSeconds(3600)));

        service.deleteProject(target.getId(), owner.getId());

        assertThat(projects.findAll()).extracting(ProjectEntity::getId).containsExactlyInAnyOrder(sibling.getId(), foreign.getId());
        assertThat(reviews.findAll()).extracting(ReviewEntity::getId).containsExactlyInAnyOrder(siblingReview, foreignReview);
        assertThat(reviews.findAllById(List.of(first, second))).isEmpty();
        assertThat(count("VulnerabilityEntity")).isEqualTo(2);
        assertThat(count("ReviewSnippetEntity")).isEqualTo(2);
        assertThat(count("ReviewScaEntity")).isEqualTo(2);
        assertThat(users.count()).isEqualTo(2);
        assertThat(connections.findAll()).extracting(GitHubConnectionEntity::getEncryptedAccessToken)
                .containsExactlyInAnyOrder("ciphertext", "other-ciphertext");
        assertThat(tx.<String>execute(status -> reviews.findById(siblingReview).orElseThrow().getRemediation().snapshotId()))
                .isEqualTo("snapshot-" + siblingReview);
        assertSnapshots(siblingReview);
        assertSnapshots(foreignReview);
    }

    @Test
    void failureAfterFlushedDependentDeletionRollsBackEntireGraph() {
        long first = review(target), second = review(target);
        doAnswer(call -> {
            reviews.flush();
            assertThat(count("ReviewScaEntity")).isZero();
            throw new IllegalStateException("injected after dependent SQL deletion");
        }).when(projects).delete(any(ProjectEntity.class));

        assertThatThrownBy(() -> service.deleteProject(target.getId(), owner.getId()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("injected");

        assertThat(projects.existsById(target.getId())).isTrue();
        assertThat(reviews.findAllById(List.of(first, second))).hasSize(2);
        assertThat(count("VulnerabilityEntity")).isEqualTo(2);
        assertThat(count("ReviewSnippetEntity")).isEqualTo(2);
        assertThat(count("ReviewScaEntity")).isEqualTo(2);
        assertThat(tx.<String>execute(status -> reviews.findById(first).orElseThrow().getRemediation().snapshotId()))
                .isEqualTo("snapshot-" + first);
        assertSnapshots(first);
        assertSnapshots(second);
    }

    @Test
    void preservesUnauthorizedForbiddenAndNotFoundAndDoesNotDelete() {
        review(target);
        var unowned = project(null, "legacy");
        expectStatus(target.getId(), null, HttpStatus.UNAUTHORIZED);
        expectStatus(target.getId(), owner.getId() + 100, HttpStatus.FORBIDDEN);
        expectStatus(unowned.getId(), owner.getId(), HttpStatus.FORBIDDEN);
        expectStatus(Long.MAX_VALUE, owner.getId(), HttpStatus.NOT_FOUND);
        assertThat(projects.count()).isEqualTo(2);
        assertThat(reviews.count()).isEqualTo(1);
    }

    @Test
    void lockConflictIs409AndLeavesAllDependentsUntouched() {
        review(target);
        doThrow(new CannotAcquireLockException("busy")).when(projects).findForDeletion(target.getId());
        expectStatus(target.getId(), owner.getId(), HttpStatus.CONFLICT);
        assertThat(projects.existsById(target.getId())).isTrue();
        assertThat(reviews.count()).isEqualTo(1);
        assertThat(count("ReviewScaEntity")).isEqualTo(1);
    }

    @Test
    void activeWorkAndNoIdReuseReservationsRefuseDeletionWithoutChangingRecords() {
        review(target);
        try (var work = lifecycle.work(target.getId())) {
            expectStatus(target.getId(), owner.getId(), HttpStatus.CONFLICT);
            assertThat(reviews.count()).isEqualTo(1);
        }
        try (var reuse = lifecycle.zip(owner.getId(), target.getName())) {
            expectStatus(target.getId(), owner.getId(), HttpStatus.CONFLICT);
        }
        service.deleteProject(target.getId(), owner.getId());
        assertThat(projects.existsById(target.getId())).isFalse();
    }

    @Test
    void deletionReservationSurvivesMethodReturnUntilOuterTransactionCommits() throws Exception {
        review(target);
        var executor = Executors.newSingleThreadExecutor();
        var returned = new CountDownLatch(1); var commit = new CountDownLatch(1);
        var deletion = executor.submit(() -> tx.executeWithoutResult(status -> {
            service.deleteProject(target.getId(), owner.getId());
            returned.countDown();
            try { if (!commit.await(5, TimeUnit.SECONDS)) throw new AssertionError("commit timeout"); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException(e); }
        }));
        try {
            assertThat(returned.await(5, TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> lifecycle.work(target.getId())).isInstanceOfSatisfying(SecureDeployException.class,
                    error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.CONFLICT));
            assertThatThrownBy(() -> lifecycle.zip(owner.getId(), target.getName())).isInstanceOf(SecureDeployException.class);
        } finally {
            commit.countDown();
            try { deletion.get(5, TimeUnit.SECONDS); } finally { executor.shutdownNow(); }
        }
        assertThat(projects.existsById(target.getId())).isFalse();
        try (var released = lifecycle.work(target.getId())) { assertThat(released).isNotNull(); }
    }

    @Test
    void rolledBackDeletionAndAllNestedReadersReleaseOnlyAtTransactionCompletion() {
        review(target);
        tx.executeWithoutResult(status -> {
            var first = lifecycle.work(target.getId()); var second = lifecycle.work(target.getId());
            var alias = lifecycle.zip(owner.getId(), target.getName());
            first.close(); second.close(); alias.close();
            expectStatus(target.getId(), owner.getId(), HttpStatus.CONFLICT);
            status.setRollbackOnly();
        });
        tx.executeWithoutResult(status -> {
            service.deleteProject(target.getId(), owner.getId());
            assertThatThrownBy(() -> lifecycle.work(target.getId())).isInstanceOf(SecureDeployException.class);
            status.setRollbackOnly();
        });
        assertThat(projects.existsById(target.getId())).isTrue();
        assertThat(reviews.count()).isEqualTo(1);
        service.deleteProject(target.getId(), owner.getId());
        assertThat(projects.existsById(target.getId())).isFalse();
    }

    @Test
    void cleanup503DoesNotUndoAlreadyCommittedReviewAndBlocksProjectDeletion(@TempDir java.nio.file.Path root) throws Exception {
        long committedReview = review(target);
        java.nio.file.Files.writeString(root.resolve("source.txt"), "synthetic");
        var lease = lifecycle.work(target.getId());
        try {
            assertThatThrownBy(() -> lease.cleanup(root, () -> { })).isInstanceOfSatisfying(SecureDeployException.class,
                    error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        } finally { lease.close(); }
        assertThat(reviews.existsById(committedReview)).isTrue();
        assertSnapshots(committedReview);
        expectStatus(target.getId(), owner.getId(), HttpStatus.CONFLICT);
    }

    @Test
    void deletionCannotEnumerateReviewsUntilExistingWriterReleasesProjectLock() throws Exception {
        review(target);
        var executor = Executors.newSingleThreadExecutor();
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        Future<?> writer = executor.submit(() -> tx.executeWithoutResult(status -> {
            var managed = projects.findForReviewCreation(target.getId()).orElseThrow();
            locked.countDown();
            try {
                if (!release.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("release timeout");
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException(e); }
            var added = new ReviewEntity("late", ReviewSourceType.ZIP, null, 1, 0, 100, "ok");
            added.assignProject(managed);
            reviews.saveAndFlush(added);
        }));
        try {
            assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
            expectStatus(target.getId(), owner.getId(), HttpStatus.CONFLICT);
            assertThat(reviews.count()).isEqualTo(1);
        } finally {
            release.countDown();
            try { writer.get(10, TimeUnit.SECONDS); }
            finally { executor.shutdownNow(); }
        }
        assertThat(reviews.count()).isEqualTo(2);
        service.deleteProject(target.getId(), owner.getId());
        assertThat(reviews.count()).isZero();
    }

    private void expectStatus(Long id, Long user, HttpStatus expected) {
        assertThatThrownBy(() -> service.deleteProject(id, user)).isInstanceOfSatisfying(
                SecureDeployException.class, error -> assertThat(error.getStatus()).isEqualTo(expected));
    }

    private ProjectEntity project(UserEntity user, String name) {
        var project = new ProjectEntity(name, ReviewSourceType.ZIP, null);
        if (user != null) project.assignUser(user);
        return projects.save(project);
    }

    private long review(ProjectEntity project) {
        return tx.execute(status -> {
            var review = new ReviewEntity(project.getName(), ReviewSourceType.ZIP, null, 1, 1, 50, "warning");
            review.assignProject(project);
            review.addVulnerability(new VulnerabilityEntity("RULE", RuleCategory.CONFIGURATION, Severity.HIGH,
                    "application.yml", 1, "finding", "fix", "evidence"));
            review.addSnippet(new ReviewSnippetEntity(SnippetType.CONFIG, "application.yml", "debug=true"));
            review.attachSourceMetadata(new com.securedeploy.github.model.GitHubSourceSnapshot("owner", "repo",
                    "https://github.com/owner/repo", "main", "abcdef", "abcdef", Instant.now(), Instant.now(),
                    Instant.now(), Instant.now(), 1, 0, 0, 0, List.of()));
            review.attachServerAnalysis(com.securedeploy.analysis.typescript.ServerAnalysisSnapshot
                    .unavailable("TEST", List.of(), "TEST_ONLY"));
            review.attachSca(new ScaResult(1, ScaResult.Status.COMPLETE, Instant.now(),
                    new ScaResult.Summary(0, 0, 0, 0, 0, Map.of()), List.of(), List.of(), List.of()));
            long id = reviews.saveAndFlush(review).getId();
            reviews.saveRemediationOnce(id, new RemediationSnapshot(1, "snapshot-" + id, Instant.now(),
                    null, List.of(), 0, List.of(), null));
            reviews.saveSemanticOnce(id, new SemanticSnapshot(1, "semantic-" + id, ScanMode.STANDARD,
                    SemanticSnapshot.Status.NOT_REQUESTED, List.of(), List.of(), List.of(), 0, 0, 0, 0,
                    "TEST", "test", "test", "v1", Instant.now(), 0, null, List.of()));
            reviews.saveComparisonOnce(id, new ReviewProgressSnapshot(1, project.getId(), null, id, null, null,
                    Instant.now(), ReviewProgressSnapshot.Status.NO_BASELINE, "test", null, null, Map.of(),
                    List.of(), List.of(), List.of(), null, null));
            return id;
        });
    }

    private void assertSnapshots(long id) {
        tx.executeWithoutResult(status -> {
            var review = reviews.findById(id).orElseThrow();
            assertThat(review.getRemediation().snapshotId()).isEqualTo("snapshot-" + id);
            assertThat(review.getSemanticReview().snapshotId()).isEqualTo("semantic-" + id);
            assertThat(review.getComparison().currentReviewId()).isEqualTo(id);
            assertThat(review.getSourceMetadata().commitSha()).isEqualTo("abcdef");
            assertThat(review.getServerAnalysis()).isNotNull();
            assertThat(review.getScaResult()).isNotNull();
        });
    }

    private long count(String entity) {
        return tx.execute(status -> em.createQuery("select count(e) from " + entity + " e", Long.class).getSingleResult());
    }
}
