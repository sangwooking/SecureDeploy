package com.securedeploy.persistence.repository;

import com.securedeploy.persistence.entity.ReviewEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ReviewRepository extends JpaRepository<ReviewEntity, Long> {

    List<ReviewEntity> findAllByOrderByCreatedAtDesc();

    @Query("select r from ReviewEntity r left join r.project p left join p.user u where p is null or u is null or u.id = :userId order by r.createdAt desc")
    List<ReviewEntity> findAllAccessibleByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId);

    List<ReviewEntity> findAllByProjectIdOrderByCreatedAtDesc(Long projectId);

    Optional<ReviewEntity> findTopByProjectIdOrderByCreatedAtDesc(Long projectId);

    @Query("select distinct r from ReviewEntity r left join fetch r.vulnerabilities where r.project.id = :projectId order by r.createdAt desc")
    List<ReviewEntity> findAllWithVulnerabilitiesByProjectIdOrderByCreatedAtDesc(@Param("projectId") Long projectId);

    default List<ReviewEntity> findTop2WithVulnerabilitiesByProjectId(Long projectId) {
        return findAllWithVulnerabilitiesByProjectIdOrderByCreatedAtDesc(projectId).stream()
                .limit(2)
                .toList();
    }

    @Query("select distinct r from ReviewEntity r left join fetch r.vulnerabilities where r.id = :id")
    Optional<ReviewEntity> findByIdWithVulnerabilities(@Param("id") Long id);
}
