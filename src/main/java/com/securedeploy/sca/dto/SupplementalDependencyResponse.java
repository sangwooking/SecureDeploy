package com.securedeploy.sca.dto;

import com.securedeploy.sca.model.DependencyVulnerability;
import com.securedeploy.sca.model.ScaEcosystem;
import java.time.Instant;
import java.util.List;

public record SupplementalDependencyResponse(
        String provenance, Status status, Instant checkedAt, ScaEcosystem ecosystem,
        String packageName, String version, List<DependencyVulnerability> findings
) {
    public enum Status { COMPLETE, PARTIAL, UNAVAILABLE, DISABLED }
}
