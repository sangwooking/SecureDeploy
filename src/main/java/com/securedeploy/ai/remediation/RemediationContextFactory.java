package com.securedeploy.ai.remediation;

import com.securedeploy.ai.context.SnippetGroup;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.risk.model.RiskFinding;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class RemediationContextFactory {
    private final RemediationSanitizer sanitizer;
    public RemediationContextFactory(RemediationSanitizer sanitizer) { this.sanitizer = sanitizer; }

    public RemediationContext create(RiskFinding finding, SecurityReviewResponse review, SnippetGroup snippets) {
        var code = review.vulnerabilities().stream().filter(v -> v.vulnerabilityId() != null
                && v.vulnerabilityId().equals(finding.vulnerabilityId())).findFirst().orElse(null);
        String path = code == null ? finding.sourceFiles().stream().findFirst().orElse(null) : code.filePath();
        String snippet = snippets.all().stream().filter(s -> s.filePath().equals(path))
                .map(s -> sanitizer.snippet(s.content())).findFirst().orElse(null);
        var dep = finding.dependency();
        var facts = finding.dependencyFacts();
        RemediationContext.DependencyContext dependency = null;
        if (dep != null) {
            var ti = review.riskAssessment().threatIntelligence();
            var ids = java.util.stream.Stream.concat(java.util.stream.Stream.of(dep.osvId()), dep.aliases().stream())
                    .distinct().limit(8).toList();
            var signals = ti == null ? List.<RemediationContext.ThreatContext>of() : ids.stream()
                    .filter(ti.cves()::containsKey).map(id -> {
                        var signal = ti.cves().get(id);
                        return new RemediationContext.ThreatContext(id,
                                signal.epss() == null ? null : signal.epss().score(),
                                signal.epss() == null ? null : signal.epss().percentile(),
                                signal.kev() == null ? null : signal.kev().knownExploited(),
                                signal.epss() == null ? "UNKNOWN" : signal.epss().status().name(),
                                signal.kev() == null ? "UNKNOWN" : signal.kev().status().name());
                    }).toList();
            dependency = new RemediationContext.DependencyContext(dep.ecosystem().name(), clean(dep.packageName(), 160),
                    clean(dep.installedVersion(), 80), dep.fixedVersions().stream().limit(12).map(v -> clean(v, 80)).toList(),
                    ids.stream().map(id -> clean(id, 80)).toList(), dep.cvssScore(), facts == null ? null : facts.direct(),
                    facts == null ? List.of() : facts.scopes().stream().limit(8).map(s -> clean(s, 80)).toList(),
                    clean(dep.summary(), 600), signals);
        }
        // The wire ID is opaque: canonical IDs can contain untrusted package names or versions.
        String wireId = java.util.UUID.nameUUIDFromBytes(finding.findingId().getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
        return new RemediationContext(wireId, finding.findingCategory(), clean(finding.ruleId(), 100),
                code != null ? code.severity().name() : dep != null && dep.severity() != null ? dep.severity().name() : null,
                finding.priority(), clean(finding.priorityReason(), 500),
                code == null || code.confidence() == null ? null : code.confidence().name(),
                code == null || code.falsePositiveRisk() == null ? null : code.falsePositiveRisk().name(),
                clean(path, 300), code == null ? null : code.line(), code == null ? null : sanitizer.snippet(code.evidence()),
                code == null ? null : clean(code.analysisNote(), 400), snippet, dependency);
    }
    private String clean(String text, int limit) { return sanitizer.text(text, limit); }
}
