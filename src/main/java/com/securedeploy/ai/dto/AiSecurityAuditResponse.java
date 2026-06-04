package com.securedeploy.ai.dto;

import java.time.LocalDateTime;
import java.util.List;

public record AiSecurityAuditResponse(
        Long reviewId,
        LocalDateTime generatedAt,
        List<String> referencedFiles,
        List<AiSecurityAuditFindingResponse> findings,
        AiUsageResponse usage
) {
}
