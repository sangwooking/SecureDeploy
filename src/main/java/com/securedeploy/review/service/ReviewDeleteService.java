package com.securedeploy.review.service;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.repository.ReviewRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ReviewDeleteService {

    private final ReviewRepository reviewRepository;

    public ReviewDeleteService(ReviewRepository reviewRepository) {
        this.reviewRepository = reviewRepository;
    }

    @Transactional
    public void deleteReview(Long reviewId, Long userId) {
        if (userId == null) {
            throw new SecureDeployException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        }

        ReviewEntity review = reviewRepository.findById(reviewId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, "분석 이력을 찾을 수 없습니다."));
        validateOwner(review, userId);
        reviewRepository.delete(review);
    }

    private void validateOwner(ReviewEntity review, Long userId) {
        ProjectEntity project = review.getProject();
        if (project == null || project.getUser() == null) {
            throw new SecureDeployException(HttpStatus.FORBIDDEN, "사용자 소유 프로젝트에 연결된 분석 결과만 삭제할 수 있습니다.");
        }
        if (!project.getUser().getId().equals(userId)) {
            throw new SecureDeployException(HttpStatus.FORBIDDEN, "이 분석 결과를 삭제할 권한이 없습니다.");
        }
    }
}
