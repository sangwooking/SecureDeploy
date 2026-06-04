package com.securedeploy.persistence.repository;

import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.review.model.ReviewSourceType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectRepository extends JpaRepository<ProjectEntity, Long> {

    List<ProjectEntity> findAllByOrderByUpdatedAtDesc();

    List<ProjectEntity> findAllByUserIdOrderByUpdatedAtDesc(Long userId);

    Optional<ProjectEntity> findByRepositoryUrl(String repositoryUrl);

    Optional<ProjectEntity> findByIdAndUserId(Long id, Long userId);

    Optional<ProjectEntity> findByRepositoryUrlAndUserId(String repositoryUrl, Long userId);

    Optional<ProjectEntity> findFirstByNameAndSourceTypeOrderByUpdatedAtDesc(String name, ReviewSourceType sourceType);

    Optional<ProjectEntity> findFirstByNameAndSourceTypeAndUserIdOrderByUpdatedAtDesc(String name, ReviewSourceType sourceType, Long userId);
}
