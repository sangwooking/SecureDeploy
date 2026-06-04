package com.securedeploy.ai.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.dto.AiComparisonInsightResponse;
import com.securedeploy.ai.dto.AiConfidence;
import com.securedeploy.ai.dto.AiPriorityItemResponse;
import com.securedeploy.ai.dto.AiProjectContext;
import com.securedeploy.ai.dto.AiProjectSummaryContent;
import com.securedeploy.ai.dto.AiRemediationResponse;
import com.securedeploy.ai.dto.AiReviewRequest;
import com.securedeploy.ai.dto.AiReviewResponse;
import com.securedeploy.ai.dto.AiRoadmapActionResponse;
import com.securedeploy.ai.dto.AiSecurityAuditFindingResponse;
import com.securedeploy.ai.dto.AiSecurityRoadmapContent;
import com.securedeploy.ai.dto.AiVulnerabilityFinding;
import com.securedeploy.ai.usage.AiTokenUsage;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

@Component
public class RealOpenAiProvider implements AiProvider {

    private static final String OPENAI_BASE_URL = "https://api.openai.com/v1";

    private final AiProperties aiProperties;
    private final ObjectMapper objectMapper;
    private final ThreadLocal<AiTokenUsage> lastTokenUsage = new ThreadLocal<>();

    public RealOpenAiProvider(AiProperties aiProperties, ObjectMapper objectMapper) {
        this.aiProperties = aiProperties;
        this.objectMapper = objectMapper;
    }

    @Override
    public AiProviderType providerType() {
        return AiProviderType.OPENAI;
    }

    @Override
    public boolean isAvailable() {
        return StringUtils.hasText(aiProperties.getOpenai().getApiKey());
    }

    @Override
    public Optional<AiTokenUsage> consumeLastTokenUsage() {
        AiTokenUsage tokenUsage = lastTokenUsage.get();
        lastTokenUsage.remove();
        return Optional.ofNullable(tokenUsage);
    }

    @Override
    public AiReviewResponse generateVulnerabilityReview(AiReviewRequest request, String prompt) {
        JsonNode json = callJsonObject(prompt);
        return new AiReviewResponse(
                request.ruleId(),
                text(json, "title", request.message()),
                text(json, "description", request.message()),
                text(json, "riskExplanation", "탐지된 취약점의 위험성을 검토해야 합니다."),
                text(json, "attackScenario", "공격자는 탐지된 약점을 악용해 접근 범위를 넓힐 수 있습니다."),
                text(json, "recommendation", request.recommendation()),
                text(json, "priority", priorityFor(request.severity()))
        );
    }

    @Override
    public AiProjectSummaryContent generateProjectSummary(AiProjectContext context, String prompt) {
        JsonNode json = callJsonObject(prompt);
        return new AiProjectSummaryContent(
                text(json, "overallSummary", "분석 결과를 기준으로 배포 전 보안 상태를 검토해야 합니다."),
                text(json, "mostRiskyArea", "가장 위험한 영역을 추가 검토해야 합니다."),
                stringList(json.path("priorityFixes")),
                List.of(text(json, "deploymentAdvice", "배포 전 주요 취약점을 수정하고 재분석하세요.")),
                text(json, "aiOpinion", "AI 보조 의견 기준으로 배포 전 보안 검토를 권장합니다.")
        );
    }

    @Override
    public List<AiRemediationResponse> generateRemediationSuggestions(AiProjectContext context, String prompt) {
        JsonNode array = callJsonArray(prompt);
        List<AiRemediationResponse> remediations = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            JsonNode item = array.get(i);
            AiVulnerabilityFinding finding = matchFinding(context, text(item, "ruleId", ""), i);
            remediations.add(new AiRemediationResponse(
                    finding.ruleId(),
                    finding.severity(),
                    finding.category(),
                    finding.filePath(),
                    finding.line(),
                    text(item, "title", finding.ruleId() + " 수정 제안"),
                    text(item, "beforeExample", "탐지된 현재 설정 또는 코드"),
                    text(item, "afterExample", finding.recommendation()),
                    text(item, "explanation", finding.recommendation()),
                    "수정 후 SecureDeploy 재분석으로 동일 ruleId가 사라졌는지 확인하세요."
            ));
        }
        return remediations;
    }

    @Override
    public List<AiSecurityAuditFindingResponse> generateSecurityAudit(AiProjectContext context, String prompt) {
        JsonNode json = callJsonObject(prompt);
        JsonNode findingsNode = json.path("findings");
        if (!findingsNode.isArray()) {
            return List.of();
        }

        List<AiSecurityAuditFindingResponse> findings = new ArrayList<>();
        for (JsonNode item : findingsNode) {
            findings.add(new AiSecurityAuditFindingResponse(
                    text(item, "title", "AI 추가 검토 의견"),
                    ruleCategory(text(item, "riskArea", "CONFIGURATION")),
                    severity(text(item, "severity", "LOW")),
                    text(item, "reasoning", "Rule Engine 결과를 기반으로 추가 검토가 권장됩니다."),
                    text(item, "possibleImpact", "운영 환경에서 보안 위험으로 이어질 가능성이 있습니다."),
                    text(item, "recommendation", "관련 코드와 설정을 수동 검토하세요."),
                    confidence(text(item, "confidence", "MEDIUM"))
            ));
        }
        return findings;
    }


    @Override
    public AiComparisonInsightResponse generateComparisonInsight(ReviewComparisonResponse comparison, String prompt) {
        JsonNode json = callJsonObject(prompt);
        return new AiComparisonInsightResponse(
                comparison.projectId(),
                comparison.latestReviewId(),
                comparison.previousReviewId(),
                text(json, "overallInsight", comparison.message()),
                text(json, "improvementSummary", "개선 내용을 추가 검토해야 합니다."),
                text(json, "remainingRiskSummary", "지속 취약점을 우선 검토해야 합니다."),
                text(json, "newRiskSummary", "신규 취약점 여부를 확인해야 합니다."),
                text(json, "deploymentReadinessOpinion", "배포 전 재분석과 수동 검토가 권장됩니다."),
                stringList(json.path("nextRecommendedActions")),
                null
        );
    }

    @Override
    public List<AiPriorityItemResponse> generatePriorities(AiProjectContext context, String prompt) {
        JsonNode json = callJsonObject(prompt);
        JsonNode prioritiesNode = json.path("priorities");
        if (!prioritiesNode.isArray()) {
            return List.of();
        }
        List<AiPriorityItemResponse> priorities = new ArrayList<>();
        for (int i = 0; i < prioritiesNode.size(); i++) {
            JsonNode item = prioritiesNode.get(i);
            priorities.add(new AiPriorityItemResponse(
                    item.path("rank").asInt(i + 1),
                    text(item, "ruleId", "UNKNOWN_RULE"),
                    text(item, "title", "수정 우선순위"),
                    severity(text(item, "severity", "LOW")),
                    text(item, "reason", "위험도와 배포 영향을 기준으로 우선순위를 산정했습니다."),
                    text(item, "expectedImpact", "보안 위험을 줄일 수 있습니다."),
                    text(item, "fixDifficulty", "보통"),
                    text(item, "recommendedAction", "수정 후 재분석하세요."),
                    text(item, "urgency", "보통")
            ));
        }
        return priorities;
    }

    @Override
    public AiSecurityRoadmapContent generateSecurityRoadmap(AiProjectContext context, String prompt) {
        JsonNode json = callJsonObject(prompt);
        return new AiSecurityRoadmapContent(
                roadmapActions(json.path("immediateActions")),
                roadmapActions(json.path("thisWeekActions")),
                roadmapActions(json.path("beforeDeploymentChecklist")),
                roadmapActions(json.path("longTermImprovements"))
        );
    }

    private JsonNode callJsonObject(String prompt) {
        JsonNode json = callOpenAi(prompt);
        JsonNode parsed = parseModelJson(extractOutputText(json));
        if (!parsed.isObject()) {
            throw new IllegalStateException("OpenAI 응답이 JSON object 형식이 아닙니다.");
        }
        return parsed;
    }

    private JsonNode callJsonArray(String prompt) {
        JsonNode json = callOpenAi(prompt);
        JsonNode parsed = parseModelJson(extractOutputText(json));
        if (!parsed.isArray()) {
            throw new IllegalStateException("OpenAI 응답이 JSON array 형식이 아닙니다.");
        }
        return parsed;
    }

    private JsonNode callOpenAi(String prompt) {
        if (!isAvailable()) {
            throw new IllegalStateException("OpenAI API Key가 설정되어 있지 않습니다.");
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", aiProperties.getOpenai().getModel());
        body.put("input", prompt);
        body.put("store", false);

        JsonNode response = restClient()
                .post()
                .uri("/responses")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + aiProperties.getOpenai().getApiKey())
                .body(body)
                .retrieve()
                .body(JsonNode.class);

        if (response == null) {
            throw new IllegalStateException("OpenAI 응답이 비어 있습니다.");
        }
        captureUsage(response);
        return response;
    }

    private RestClient restClient() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        Duration timeout = Duration.ofSeconds(Math.max(1, aiProperties.getOpenai().getTimeoutSeconds()));
        requestFactory.setConnectTimeout(timeout);
        requestFactory.setReadTimeout(timeout);
        return RestClient.builder()
                .baseUrl(OPENAI_BASE_URL)
                .requestFactory(requestFactory)
                .build();
    }

    private void captureUsage(JsonNode response) {
        JsonNode usage = response.path("usage");
        if (usage.isMissingNode() || usage.isNull()) {
            lastTokenUsage.set(new AiTokenUsage(0, 0, 0, true));
            return;
        }

        int inputTokens = usage.path("input_tokens").asInt(0);
        int outputTokens = usage.path("output_tokens").asInt(0);
        int totalTokens = usage.path("total_tokens").asInt(inputTokens + outputTokens);
        lastTokenUsage.set(new AiTokenUsage(inputTokens, outputTokens, totalTokens, true));
    }

    private JsonNode parseModelJson(String outputText) {
        String normalized = stripMarkdownFence(outputText).trim();
        int objectStart = normalized.indexOf('{');
        int arrayStart = normalized.indexOf('[');
        boolean arrayFirst = arrayStart >= 0 && (objectStart < 0 || arrayStart < objectStart);

        int start = arrayFirst ? arrayStart : objectStart;
        int end = arrayFirst ? normalized.lastIndexOf(']') : normalized.lastIndexOf('}');
        if (start < 0 || end < start) {
            throw new IllegalStateException("OpenAI 응답에서 JSON 본문을 찾지 못했습니다.");
        }

        try {
            return objectMapper.readTree(normalized.substring(start, end + 1));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("OpenAI JSON 응답 파싱에 실패했습니다.", e);
        }
    }

    private String extractOutputText(JsonNode response) {
        String outputText = response.path("output_text").asText("");
        if (StringUtils.hasText(outputText)) {
            return outputText;
        }

        StringBuilder builder = new StringBuilder();
        JsonNode output = response.path("output");
        if (output.isArray()) {
            for (JsonNode outputItem : output) {
                JsonNode content = outputItem.path("content");
                if (content.isArray()) {
                    for (JsonNode contentItem : content) {
                        String text = contentItem.path("text").asText("");
                        if (StringUtils.hasText(text)) {
                            builder.append(text).append('\n');
                        }
                    }
                }
            }
        }

        if (!StringUtils.hasText(builder.toString())) {
            throw new IllegalStateException("OpenAI 응답에서 output text를 찾지 못했습니다.");
        }
        return builder.toString();
    }

    private String stripMarkdownFence(String value) {
        String trimmed = value == null ? "" : value.trim();
        if (trimmed.startsWith("```")) {
            int firstLineEnd = trimmed.indexOf('\n');
            int lastFence = trimmed.lastIndexOf("```");
            if (firstLineEnd >= 0 && lastFence > firstLineEnd) {
                return trimmed.substring(firstLineEnd + 1, lastFence);
            }
        }
        return trimmed;
    }

    private AiVulnerabilityFinding matchFinding(AiProjectContext context, String ruleId, int index) {
        if (StringUtils.hasText(ruleId)) {
            for (AiVulnerabilityFinding finding : context.findings()) {
                if (finding.ruleId().equals(ruleId)) {
                    return finding;
                }
            }
        }
        if (index >= 0 && index < context.findings().size()) {
            return context.findings().get(index);
        }
        return new AiVulnerabilityFinding("AI_REMEDIATION", Severity.LOW, RuleCategory.CONFIGURATION, "-", 0,
                "AI 수정 제안", "수정 후 재분석하세요.", null);
    }


    private List<AiRoadmapActionResponse> roadmapActions(JsonNode node) {
        if (!node.isArray()) {
            return List.of();
        }
        List<AiRoadmapActionResponse> actions = new ArrayList<>();
        for (JsonNode item : node) {
            actions.add(new AiRoadmapActionResponse(
                    text(item, "title", "보안 개선 작업"),
                    text(item, "description", "보안 개선을 진행합니다."),
                    stringList(item.path("relatedRuleIds")),
                    text(item, "reason", "탐지 결과를 기반으로 필요한 조치입니다."),
                    text(item, "expectedBenefit", "보안 위험을 줄일 수 있습니다.")
            ));
        }
        return actions;
    }

    private List<String> stringList(JsonNode node) {
        if (!node.isArray()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        for (JsonNode item : node) {
            if (StringUtils.hasText(item.asText())) {
                values.add(item.asText());
            }
        }
        return values;
    }

    private String text(JsonNode node, String fieldName, String fallback) {
        String value = node.path(fieldName).asText("");
        return StringUtils.hasText(value) ? value : fallback;
    }

    private RuleCategory ruleCategory(String value) {
        try {
            return RuleCategory.valueOf(value);
        } catch (IllegalArgumentException e) {
            return RuleCategory.CONFIGURATION;
        }
    }

    private Severity severity(String value) {
        try {
            return Severity.valueOf(value);
        } catch (IllegalArgumentException e) {
            return Severity.LOW;
        }
    }

    private AiConfidence confidence(String value) {
        try {
            return AiConfidence.valueOf(value);
        } catch (IllegalArgumentException e) {
            return AiConfidence.MEDIUM;
        }
    }

    private String priorityFor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "즉시 수정";
            case HIGH -> "높은 우선순위";
            case MEDIUM -> "계획된 수정";
            case LOW -> "점검 권장";
        };
    }
}
