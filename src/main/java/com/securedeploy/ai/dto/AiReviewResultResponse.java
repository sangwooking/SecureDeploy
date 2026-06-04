package com.securedeploy.ai.dto;

import java.time.LocalDateTime;
import java.util.List;

public record AiReviewResultResponse(
        Long reviewId,
        LocalDateTime generatedAt,
        List<AiReviewResponse> reviews,
        AiUsageResponse usage
) {
}
