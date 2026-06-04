package com.securedeploy.ai.dto;

import java.time.LocalDateTime;
import java.util.List;

public record AiPriorityResponse(
        Long reviewId,
        LocalDateTime generatedAt,
        List<AiPriorityItemResponse> priorities,
        AiUsageResponse usage
) {
}
