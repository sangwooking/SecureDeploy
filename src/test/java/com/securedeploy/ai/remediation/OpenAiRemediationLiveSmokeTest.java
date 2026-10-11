package com.securedeploy.ai.remediation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.context.SnippetGroup;
import com.securedeploy.ai.prompt.PromptBuilder;
import com.securedeploy.ai.service.*;
import com.securedeploy.ai.usage.TemplateAiUsageTracker;
import com.securedeploy.rule.model.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import static org.assertj.core.api.Assertions.*;

@EnabledIfEnvironmentVariable(named = "SECUREDEPLOY_OPENAI_SMOKE", matches = "true")
class OpenAiRemediationLiveSmokeTest {
    @Test void generatesAdviceFromSyntheticFindingWithoutChangingRisk() {
        String key = System.getenv("OPENAI_API_KEY");
        org.junit.jupiter.api.Assumptions.assumeTrue(key != null && !key.isBlank(), "OPENAI_API_KEY required");
        var props = new AiProperties();
        props.setProvider(AiProviderType.OPENAI);
        props.getOpenai().setApiKey(key);
        props.getOpenai().setModel(System.getenv().getOrDefault("OPENAI_MODEL", "gpt-5.4-mini"));
        var mapper = new ObjectMapper();
        var sanitizer = new RemediationSanitizer();
        var generator = new FindingRemediationService(new AiProviderResolver(props,
                List.of(new TemplateAiProvider(), new RealOpenAiProvider(props, mapper))), props,
                new RemediationContextFactory(sanitizer), sanitizer, new PromptBuilder(), mapper, new TemplateAiUsageTracker(props));
        var review = new FindingRemediationTest().codeReview("DEBUG_ENABLED", DetectionConfidence.HIGH, FalsePositiveRisk.LOW);
        var risk = review.riskAssessment();
        var snapshot = generator.generate(review, SnippetGroup.empty());
        assertThat(snapshot.findings().get(0).generationStatus()).isEqualTo(RemediationAdvice.GenerationStatus.GENERATED);
        assertThat(snapshot.usage().billable()).isTrue();
        assertThat(review.riskAssessment()).isSameAs(risk);
    }
}
