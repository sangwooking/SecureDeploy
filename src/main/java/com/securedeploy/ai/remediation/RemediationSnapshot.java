package com.securedeploy.ai.remediation;

import com.securedeploy.ai.dto.AiUsageResponse;
import java.time.Instant;
import java.util.List;

public record RemediationSnapshot(int schemaVersion, String snapshotId, Instant generatedAt,
                                  RemediationAdvice.GenerationStatus generationStatus,
                                  List<RemediationAdvice> findings, int omittedFindingCount,
                                  List<String> notices, AiUsageResponse usage) { }
