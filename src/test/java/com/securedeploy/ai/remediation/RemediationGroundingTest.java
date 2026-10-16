package com.securedeploy.ai.remediation;

import com.securedeploy.ai.dto.AiConfidence;
import com.securedeploy.risk.model.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class RemediationGroundingTest {
    private final RemediationContext context = new RemediationContext("fixture", FindingCategory.DEPENDENCY, null,
            "HIGH", RiskPriority.SHOULD_FIX, "fixture", null, null, "pom.xml", null, null, null, null,
            new RemediationContext.DependencyContext("MAVEN", "fixture:fixture", "1.0.0", List.of("1.2.3"),
                    List.of("CVE-2099-0001"), 9.8, true, List.of("runtime"), "Synthetic advisory",
                    List.of(new RemediationContext.ThreatContext("CVE-2099-0001", .95, .99, true, "AVAILABLE", "AVAILABLE"))));

    @Test void legitimateThreatNumbersAreNotPackageVersions() {
        assertThatCode(() -> RemediationOutputValidator.validate(advice(
                "CVSS 9.8, EPSS 0.95, EPSS percentile 0.99; 저장된 수정 버전 1.2.3을 검토하세요."), context)).doesNotThrowAnyException();
        assertThatCode(() -> RemediationOutputValidator.validate(advice(
                "EPSS 95%, EPSS percentile 99%; 프로젝트 해킹 확률이 아닙니다."), context)).doesNotThrowAnyException();
    }
    @Test void metricValueDoesNotAuthorizePackageVersion() {
        assertThatThrownBy(() -> RemediationOutputValidator.validate(advice("CVSS 9.8; upgrade to 9.8"), context))
                .isInstanceOf(RemediationValidationException.class).hasMessage("UNSUPPORTED_VERSION_REFERENCE");
    }
    @Test void inventedMetricAndInventedVersionStillFailClosed() {
        for (String text : List.of("CVSS 9.7", "EPSS 0.72", "upgrade to 999.0.0", "EPSS percentile 95.0")) {
            assertThatThrownBy(() -> RemediationOutputValidator.validate(advice(text), context))
                    .isInstanceOf(RemediationValidationException.class).hasMessage("UNSUPPORTED_VERSION_REFERENCE");
        }
    }
    @Test void unresolvedDependencyTemplateRequestsFactsWithoutInventingFixes() {
        var unresolved = new RemediationContext("unresolved:fixture", FindingCategory.DEPENDENCY, null,
                null, RiskPriority.REVIEW_REQUIRED, "버전 미확인", null, null, "build.gradle.kts", null,
                null, null, null, null);
        var advice = RemediationTemplates.advice(unresolved);
        assertThat(advice.recommendedAction()).contains("이름과 실제 사용 버전", "안내할 수 없습니다");
        assertThat(advice.codeExample()).isNull();
        assertThat(advice.configurationExample()).isNull();
        assertThat(advice.summary()).doesNotContain("unresolved-package", "최신 버전");
        assertThat(advice.verificationSteps()).anyMatch(step -> step.contains("재검사"));
    }
    private RemediationContent advice(String explanation) {
        return new RemediationContent("Synthetic advice", explanation, "Verify the official advisory", "", "",
                List.of("Run regression tests and rescan"), "Verify compatibility", AiConfidence.MEDIUM);
    }
}
