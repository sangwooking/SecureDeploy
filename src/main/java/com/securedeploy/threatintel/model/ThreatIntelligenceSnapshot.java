package com.securedeploy.threatintel.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record ThreatIntelligenceSnapshot(String snapshotId, Instant observedAt, Status status,
                                         int requestedCves, int findingsWithoutCve,
                                         Map<String, ThreatIntelligence> cves, List<String> warnings) {
    public enum Status { COMPLETE, PARTIAL, UNAVAILABLE, STALE, NOT_APPLICABLE, DISABLED, UNKNOWN }
}
