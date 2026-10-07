package com.securedeploy.risk.policy;

import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.model.RiskFinding.DependencyFacts;
import com.securedeploy.rule.model.*;
import com.securedeploy.sca.model.DependencyVulnerability;
import java.util.Set;
import org.springframework.stereotype.Component;
import static com.securedeploy.risk.model.RiskPriority.*;
import static com.securedeploy.risk.policy.RiskReason.*;

@Component
public class DefaultRiskPolicy implements RiskPolicy {
    // Only rules with direct configuration/credential evidence are eligible to block.
    private static final Set<String> CREDENTIAL_RULES = Set.of(
            "HARDCODED_PASSWORD", "HARDCODED_SECRET", "HARDCODED_FRONTEND_SECRET", "DOCKER_SECRET_ENV");
    private static final Set<String> CONTEXT_REQUIRED = Set.of(
            "DANGEROUS_SQL", "PERMIT_ALL_USAGE", "CORS_WILDCARD", "REACT_DANGEROUS_HTML",
            "UNVALIDATED_REDIRECT", "EXPOSED_ACTUATOR", "K8S_SECRET_PLAIN_TEXT",
            "VULNERABLE_NPM_DEPENDENCY", "VULNERABLE_MAVEN_DEPENDENCY", "VULNERABLE_GRADLE_DEPENDENCY");
    // A separate policy entry can promote a MEDIUM finding without rewriting its severity.
    private static final Set<String> BLOCKING_CONFIG_RULES = Set.of("GITHUB_ACTIONS_SECRET_ECHO");

    @Override public String version() { return "risk-v1.1"; }

    @Override public Decision code(VulnerabilityResultResponse f) {
        if (f.severity() == null || f.confidence() == null || f.falsePositiveRisk() == null
                || f.analysisNote() == null || f.analysisNote().isBlank()) {
            return new Decision(REVIEW_REQUIRED, MISSING_METADATA);
        }
        if (f.confidence() == DetectionConfidence.LOW || f.falsePositiveRisk() == FalsePositiveRisk.HIGH) {
            return new Decision(REVIEW_REQUIRED, UNCERTAIN_FINDING);
        }
        if (CONTEXT_REQUIRED.contains(f.ruleId())) return new Decision(REVIEW_REQUIRED, PATTERN_REQUIRES_CONTEXT);
        boolean strong = f.confidence() == DetectionConfidence.HIGH && f.falsePositiveRisk() == FalsePositiveRisk.LOW;
        boolean high = f.severity() == Severity.HIGH || f.severity() == Severity.CRITICAL;
        if (strong && high && CREDENTIAL_RULES.contains(f.ruleId())) return new Decision(BLOCKING, CONFIRMED_SECRET);
        if (strong && (high || f.severity() == Severity.MEDIUM) && BLOCKING_CONFIG_RULES.contains(f.ruleId())) {
            return new Decision(BLOCKING, STRONG_CONFIGURATION);
        }
        if (!strong && high) return new Decision(REVIEW_REQUIRED, UNCERTAIN_FINDING);
        if (f.severity() == Severity.LOW && strong) return new Decision(INFORMATIONAL, CODE_INFORMATIONAL);
        return new Decision(SHOULD_FIX, CODE_FIX_RECOMMENDED);
    }

    @Override public Decision dependency(DependencyVulnerability f, DependencyFacts facts) {
        if (!facts.exactVersion() || !facts.lookupConfirmed()) return new Decision(REVIEW_REQUIRED, INCOMPLETE_SCA);
        Severity severity = f.severity();
        Double score = f.cvssScore();
        if (score != null && Double.isFinite(score) && score >= 0 && score <= 10) {
            Severity scored = score >= 9 ? Severity.CRITICAL : score >= 7 ? Severity.HIGH : score >= 4 ? Severity.MEDIUM : Severity.LOW;
            if (severity == null || scored.ordinal() > severity.ordinal()) severity = scored;
        }
        if (severity == null) return new Decision(REVIEW_REQUIRED, UNKNOWN_DEPENDENCY_SEVERITY);
        return switch (severity) {
            case CRITICAL -> new Decision(BLOCKING, CRITICAL_DEPENDENCY);
            case HIGH, MEDIUM -> new Decision(SHOULD_FIX, DEPENDENCY_FIX_RECOMMENDED);
            case LOW -> new Decision(INFORMATIONAL, DEPENDENCY_INFORMATIONAL);
        };
    }
}
