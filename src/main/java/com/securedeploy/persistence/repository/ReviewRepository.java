package com.securedeploy.persistence.repository;

import com.securedeploy.persistence.entity.ReviewEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ReviewRepository extends JpaRepository<ReviewEntity, Long> {

    Optional<ReviewEntity> findTopByProjectIdOrderByCreatedAtDescIdDesc(Long projectId);

    @org.springframework.data.jpa.repository.Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update ReviewEntity r set r.comparison = :snapshot where r.id = :id and r.comparison is null")
    int saveComparisonOnce(@Param("id") Long id,
            @Param("snapshot") com.securedeploy.project.progress.ReviewProgressSnapshot snapshot);

    @org.springframework.data.jpa.repository.Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update ReviewEntity r set r.semanticReview = :snapshot where r.id = :id and r.semanticReview is null")
    int saveSemanticOnce(@Param("id") Long id, @Param("snapshot") com.securedeploy.ai.semantic.SemanticSnapshot snapshot);

    @org.springframework.data.jpa.repository.Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update ReviewEntity r set r.remediation = :snapshot where r.id = :id and r.remediation is null")
    int saveRemediationOnce(@Param("id") Long id,
            @Param("snapshot") com.securedeploy.ai.remediation.RemediationSnapshot snapshot);

    List<ReviewEntity> findAllByOrderByCreatedAtDesc();

    @Query("select r from ReviewEntity r join r.project p where p.user.id = :userId order by r.createdAt desc, r.id desc")
    List<ReviewEntity> findAllAccessibleByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId);

    List<ReviewEntity> findAllByProjectIdOrderByCreatedAtDesc(Long projectId);

    Optional<ReviewEntity> findTopByProjectIdOrderByCreatedAtDesc(Long projectId);

    @Query("select r from ReviewEntity r where r.project.id = :projectId order by r.createdAt desc, r.id desc")
    List<ReviewEntity> findProjectReviewsForCollectionLoading(@Param("projectId") Long projectId);

    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    default List<ReviewEntity> findAllWithVulnerabilitiesByProjectIdOrderByCreatedAtDesc(Long projectId) {
        var result=findProjectReviewsForCollectionLoading(projectId);
        result.forEach(r->r.getVulnerabilities().size());
        return result;
    }

    default List<ReviewEntity> findTop2WithVulnerabilitiesByProjectId(Long projectId) {
        return findAllWithVulnerabilitiesByProjectIdOrderByCreatedAtDesc(projectId).stream()
                .limit(2)
                .toList();
    }

    // A fetch join repeats the potentially large JSON snapshots for EVERY Finding.
    // Load the parent once, then initialize only its bounded collection in the same transaction.
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    default Optional<ReviewEntity> findByIdWithVulnerabilities(Long id) {
        var result=findById(id);
        result.ifPresent(r->r.getVulnerabilities().size());
        return result;
    }

    @Query("select r from ReviewEntity r join fetch r.project p where p.user.id = :userId and not exists "
            + "(select newer.id from ReviewEntity newer where newer.project.id = p.id and "
            + "(newer.createdAt > r.createdAt or (newer.createdAt = r.createdAt and newer.id > r.id))) order by r.createdAt desc, r.id desc")
    List<ReviewEntity> findLatestByOwner(@Param("userId") Long userId);

    interface ProjectReviewCount {
        Long getProjectId();
        long getReviewCount();
    }

    @Query("select r.project.id as projectId, count(r) as reviewCount from ReviewEntity r "
            + "where r.project.user.id = :userId group by r.project.id")
    List<ProjectReviewCount> countReviewsByOwner(@Param("userId") Long userId);
}
