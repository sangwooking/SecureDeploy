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

    @Query("select distinct r from ReviewEntity r left join fetch r.vulnerabilities where r.project.id = :projectId order by r.createdAt desc, r.id desc")
    List<ReviewEntity> findAllWithVulnerabilitiesByProjectIdOrderByCreatedAtDesc(@Param("projectId") Long projectId);

    default List<ReviewEntity> findTop2WithVulnerabilitiesByProjectId(Long projectId) {
        return findAllWithVulnerabilitiesByProjectIdOrderByCreatedAtDesc(projectId).stream()
                .limit(2)
                .toList();
    }

    @Query("select distinct r from ReviewEntity r left join fetch r.vulnerabilities where r.id = :id")
    Optional<ReviewEntity> findByIdWithVulnerabilities(@Param("id") Long id);

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
