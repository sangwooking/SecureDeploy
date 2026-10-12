package com.securedeploy.ai.remediation;

import com.securedeploy.ai.context.SnippetGroup;
import com.securedeploy.persistence.service.ReviewPersistenceService;
import com.securedeploy.review.dto.SecurityReviewResponse;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class RemediationSnapshotService {
    private final FindingRemediationService generator;
    private final ReviewPersistenceService persistence;
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(RemediationSnapshotService.class);
    public RemediationSnapshotService(FindingRemediationService generator, ReviewPersistenceService persistence) {
        this.generator = generator; this.persistence = persistence;
    }

    // Called only after the deterministic review transaction commits, never on history reads.
    public SecurityReviewResponse complete(SecurityReviewResponse saved, SnippetGroup snippets) {
        return complete(saved, snippets, true);
    }

    public SecurityReviewResponse complete(SecurityReviewResponse saved, SnippetGroup snippets, boolean allowExternalAi) {
        if (saved.remediation() != null) return saved;
        RemediationSnapshot snapshot;
        try { snapshot = generator.generate(saved, snippets, allowExternalAi); }
        catch (RuntimeException failure) {
            snapshot = new RemediationSnapshot(1, UUID.randomUUID().toString(), Instant.now(),
                    RemediationAdvice.GenerationStatus.UNAVAILABLE, List.of(), 0,
                    List.of("해결 가이드를 생성하지 못했습니다. 저장된 보안 판단은 유지됩니다."), null);
            LOG.warn("Remediation unavailable for review {}", saved.reviewId());
        }
        try { return persistence.saveRemediationSnapshot(saved.reviewId(), snapshot); }
        catch (RuntimeException failure) {
            LOG.warn("Remediation snapshot persistence failed for review {}", saved.reviewId());
            // Do not claim an ephemeral result was persisted. History remains legacy/null compatible.
            return saved;
        }
    }
}
