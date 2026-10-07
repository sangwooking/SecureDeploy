package com.securedeploy.risk.model;

import com.securedeploy.dependency.model.DependencyObservation;
import java.util.List;

public record DependencyCorrelation(Long vulnerabilityId, String ruleId, String filePath, int line,
                                    DependencyObservation observation, Relation relation,
                                    List<String> canonicalFindingIds, String reason) {
    public enum Relation { SAME_ADVISORY, PACKAGE_CANDIDATE_CONTEXT, REPEATED_CATALOG_OBSERVATION }
}
