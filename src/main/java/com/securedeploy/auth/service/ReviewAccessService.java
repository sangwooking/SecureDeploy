package com.securedeploy.auth.service;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.repository.ReviewRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class ReviewAccessService {

    private final ReviewRepository reviewRepository;
    private final CurrentUserService currentUserService;

    public ReviewAccessService(ReviewRepository reviewRepository, CurrentUserService currentUserService) {
        this.reviewRepository = reviewRepository;
        this.currentUserService = currentUserService;
    }

    public ReviewEntity findAccessibleReviewWithVulnerabilities(Long reviewId, String notFoundMessage) {
        ReviewEntity review = reviewRepository.findByIdWithVulnerabilities(reviewId)
                .orElseThrow(() -> new SecureDeployException(HttpStatus.NOT_FOUND, notFoundMessage));
        validateReviewAccess(review);
        return review;
    }

    public void validateReviewAccess(ReviewEntity review) {
        ProjectOwnership.requireOwner(review.getProject(), currentUserService.currentUserId());
    }
}
