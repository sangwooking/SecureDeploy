package com.securedeploy.ai.dto;

import java.time.LocalDateTime;
import java.util.List;

public record AiRemediationResultResponse(
        Long reviewId,
        LocalDateTime generatedAt,
        List<AiRemediationResponse> remediations,
        AiUsageResponse usage
) {
}
