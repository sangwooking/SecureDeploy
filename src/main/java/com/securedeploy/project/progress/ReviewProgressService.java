package com.securedeploy.project.progress;

import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.persistence.service.ReviewPersistenceService;
import com.securedeploy.review.dto.SecurityReviewResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ReviewProgressService {
    private final ReviewRepository reviews;
    private final ReviewPersistenceService persistence;
    private final ProgressComparisonEngine engine;
    public ReviewProgressService(ReviewRepository reviews, ReviewPersistenceService persistence, ProgressComparisonEngine engine) {
        this.reviews = reviews; this.persistence = persistence; this.engine = engine;
    }

    @Transactional
    public SecurityReviewResponse complete(SecurityReviewResponse response) {
        var current = reviews.findByIdWithVulnerabilities(response.reviewId()).orElseThrow();
        var context = current.getComparisonContext();
        if (context != null && current.getComparison() == null) {
            var before = context.baselineReviewId() == null ? null
                    : reviews.findByIdWithVulnerabilities(context.baselineReviewId()).orElse(null);
            reviews.saveComparisonOnce(current.getId(), engine.compare(before, current));
        }
        return persistence.findReviewDetail(response.reviewId());
    }
}
