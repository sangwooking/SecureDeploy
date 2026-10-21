package com.securedeploy.ai.remediation;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertTimeout;

class RemediationMaskingBudgetTest {
    @Test void longNonAssignmentIdentifierDoesNotRestartCredentialSearchAtEveryCharacter() {
        assertTimeout(Duration.ofSeconds(2),()-> {
            String safe=new RemediationSanitizer().text("/*"+"x".repeat(250_001)+" http://docs.example */",10_000);
            assertThat(safe).contains("<redacted>").doesNotContain("x".repeat(32));
        });
    }
    @Test void prefixedAndQuotedAssignmentsStillMaskBeforeTruncation() {
        var sanitizer=new RemediationSanitizer();
        for(String prefix:new String[]{"private.api_key", "APP_SECRET", "\"accessToken\"", "password"}) {
            String text=sanitizer.text(prefix+"='synthetic-value-not-a-real-credential';",10_000);
            assertThat(text).contains("<redacted>").doesNotContain("synthetic-value-not-a-real-credential");
        }
        assertThat(sanitizer.text("API_SECRET=${SERVER_VALUE}",100)).contains("${SERVER_VALUE}");
    }
}
