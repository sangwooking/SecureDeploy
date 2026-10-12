package com.securedeploy.ai.semantic;

import com.securedeploy.persistence.service.ReviewPersistenceService;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.model.ScanMode;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class SemanticSnapshotService {
    private final SemanticReviewService generator;
    private final ReviewPersistenceService persistence;
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(SemanticSnapshotService.class);
    public SemanticSnapshotService(SemanticReviewService generator, ReviewPersistenceService persistence) {
        this.generator=generator; this.persistence=persistence;
    }
    public SecurityReviewResponse complete(SecurityReviewResponse saved, ScanMode mode, SecuritySliceCollector.Collection slices) {
        if (saved.semanticReview()!=null) return saved;
        SemanticSnapshot snapshot;
        try { snapshot = generator.generate(saved,mode,slices); }
        catch (RuntimeException failure) { snapshot = SemanticReviewService.empty(mode,SemanticSnapshot.Status.FAILED,"Semantic review unavailable.",List.of()); }
        try { return persistence.saveSemanticSnapshot(saved.reviewId(),snapshot); }
        catch (RuntimeException failure) {
            LOG.warn("Semantic snapshot persistence failed for review {}",saved.reviewId());
            return saved;
        }
    }
}
