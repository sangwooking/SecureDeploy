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
import java.util.Objects;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

@Component
public class RealOpenAiProvider implements AiProvider {
    @Override public com.securedeploy.editing.WorkspacePatchPlan.Output generateWorkspacePatchPlan(com.securedeploy.editing.WorkspacePatch.Prompt prompt){return com.securedeploy.editing.WorkspacePatchPlan.parse(structuredOutput("workspace_patch_plan_v1",prompt));}
    @Override public String executionOrigin() { return "OPENAI"; }
    @Override
    public com.securedeploy.editing.WorkspacePatch.Output generateWorkspacePatch(com.securedeploy.editing.WorkspacePatch.Prompt prompt) {
        return com.securedeploy.editing.WorkspacePatch.parse(structuredOutput("workspace_patch_v1",prompt));
    }

    @Override
    public com.securedeploy.ai.dependency.DependencyAiAdvice.Output generateDependencyAdvice(com.securedeploy.editing.WorkspacePatch.Prompt prompt) {
        return com.securedeploy.ai.dependency.DependencyAiAdvice.parse(structuredOutput("dependency_update_advice_v1",prompt),objectMapper);
    }

    private JsonNode structuredOutput(String schemaName, com.securedeploy.editing.WorkspacePatch.Prompt prompt) {
        return structuredOutput(schemaName,prompt,2000,8192);
    }
    private JsonNode structuredOutput(String schemaName, com.securedeploy.editing.WorkspacePatch.Prompt prompt,int maxOutputTokens,int maxTextChars) {
        lastTokenUsage.remove();
        if(!isAvailable())throw new AiProviderFailure(AiProviderFailure.Kind.NOT_SENT,false);
        var body=new LinkedHashMap<String,Object>();
        body.put("model",aiProperties.getOpenai().getModel());body.put("store",false);
        body.put("instructions",prompt.instructions());body.put("input",List.of(Map.of("role","user","content",prompt.untrustedData())));
        body.put("max_output_tokens",maxOutputTokens);
        body.put("text",Map.of("format",Map.of("type","json_schema","name",schemaName,"strict",true,"schema",prompt.schema())));
        try {if(objectMapper.writeValueAsBytes(body).length>30720||maxOutputTokens>4000)throw new IllegalArgumentException("AI request budget exceeded");}
        catch(com.fasterxml.jackson.core.JsonProcessingException invalid){throw new IllegalArgumentException("AI request encoding failed");}
        var response=guardedSend(body,schemaName,maxOutputTokens);
        captureUsage(response);
        if(!"completed".equals(response.path("status").asText()))throw new AiProviderFailure(AiProviderFailure.Kind.INCOMPLETE,true);
        for(var item:response.path("output")) for(var content:item.path("content"))
            if("refusal".equals(content.path("type").asText()))throw new AiProviderFailure(AiProviderFailure.Kind.REFUSED,true);
        try {
            String text=extractOutputText(response);
            if(text.length()>maxTextChars)throw new IllegalArgumentException("Patch output limit");
            var tree=objectMapper.reader().with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
                    .with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .with(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION).readTree(text);
            return tree;
        } catch(java.io.IOException invalid){throw new AiProviderFailure(AiProviderFailure.Kind.INVALID_RESPONSE,true);}
    }

    @Override
    public List<com.securedeploy.ai.semantic.SemanticCandidate.Proposal> generateSemanticReview(
            List<com.securedeploy.ai.semantic.SecuritySlice> slices, com.securedeploy.ai.semantic.SemanticPrompt prompt) {
        var request=new com.securedeploy.editing.WorkspacePatch.Prompt(prompt.instructions(),prompt.untrustedData(),com.securedeploy.ai.semantic.SemanticOutputValidator.schema(slices));
        return com.securedeploy.ai.semantic.SemanticOutputValidator.parse(structuredOutput("semantic_review",request,prompt.maxOutputTokens(),48000),objectMapper);
    }

    @Override
    public Map<String, com.securedeploy.ai.remediation.RemediationContent> generateFindingRemediations(
            List<com.securedeploy.ai.remediation.RemediationContext> contexts,
            com.securedeploy.ai.remediation.RemediationPrompt prompt) {
        lastTokenUsage.remove();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", aiProperties.getOpenai().getModel());
        body.put("store", false);
        body.put("instructions", prompt.instructions());
        body.put("input", List.of(Map.of("role", "user", "content", prompt.untrustedData())));
        body.put("max_output_tokens", 6_000);
        body.put("text", Map.of("format", Map.of("type", "json_schema", "name", "finding_remediation",
                "strict", true, "schema", com.securedeploy.ai.remediation.RemediationOutputValidator.schema(contexts))));
        var response = sendOpenAi(body);
        if (!"completed".equals(response.path("status").asText())) throw new IllegalStateException("Incomplete remediation response");
        try {
            var json = objectMapper.readTree(extractOutputText(response));
            return com.securedeploy.ai.remediation.RemediationOutputValidator.parse(json, contexts, objectMapper);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Invalid remediation JSON");
        }
    }

    private static final String OPENAI_BASE_URL = "https://api.openai.com/v1";

    private final AiProperties aiProperties;
    private final ObjectMapper objectMapper;
    private final RestClient testClient;
    private com.securedeploy.ai.usage.DurableAiLedger ledger;
    @org.springframework.beans.factory.annotation.Autowired
    void configureLedger(com.securedeploy.ai.usage.DurableAiLedger ledger){this.ledger=ledger;}
    private final ThreadLocal<AiTokenUsage> lastTokenUsage = new ThreadLocal<>();

    @org.springframework.beans.factory.annotation.Autowired
    public RealOpenAiProvider(AiProperties aiProperties, ObjectMapper objectMapper) {
        this(aiProperties, objectMapper, null);
    }

    RealOpenAiProvider(AiProperties aiProperties, ObjectMapper objectMapper, RestClient testClient) {
        this.aiProperties = aiProperties;
        this.objectMapper = objectMapper;
        this.testClient = testClient;
    }

    @Override
    public AiProviderType providerType() {
        return AiProviderType.OPENAI;
    }

    @Override
    public boolean isAvailable() {
        return StringUtils.hasText(aiProperties.getOpenai().getApiKey()) && (ledger!=null && ledger.enabled());
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

        return sendOpenAi(body);
    }

    private JsonNode sendOpenAi(Map<String, Object> body) {
        if (!isAvailable()) throw new IllegalStateException("OpenAI is not configured");

        // Legacy summary/PDF/explanation calls have no per-request consent UI and are denied by the gate.
        return guardedSend(body,"LEGACY_UNCONSENTED",4000);
    }

    private JsonNode guardedSend(Map<String,Object> body,String feature,int maxOutput){
        lastTokenUsage.remove();String admission=null;
        body.putIfAbsent("max_output_tokens",maxOutput);
        try {
            if(objectMapper.writeValueAsBytes(body).length>30720||maxOutput>4000)throw new IllegalArgumentException("AI request budget exceeded");
        }catch(java.io.IOException bad){throw new IllegalArgumentException("AI request encoding failed");}
        try {
            if(ledger==null)throw new IllegalStateException("Durable AI admission unavailable");
            String instructions=Objects.toString(body.get("instructions"),"");
            Object input=body.get("input");String data;
            if(input instanceof List<?> list && list.size()==1 && list.get(0) instanceof Map<?,?> message && message.get("content") instanceof String text)data=text;
            else throw new IllegalStateException("Legacy AI requests require a separate consent contract");
            admission=ledger.reserve(com.securedeploy.ai.usage.AiAdmission.current(),feature,aiProperties.getOpenai().getModel(),
                com.securedeploy.ai.usage.AiAdmission.hash(instructions+"\0"+data),32768,maxOutput);
            ledger.sending(admission); // Commit before the network boundary. Uncertain outcomes never retry.
        } catch(RuntimeException denied) {throw new AiProviderFailure(AiProviderFailure.Kind.NOT_SENT,false);}
        try {
            try {ledger.requireTransmissionOpen();}
            catch(IllegalStateException closed){throw new AiProviderFailure(AiProviderFailure.Kind.NOT_SENT,false);}
            var response=restClient().post().uri("/responses").contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION,"Bearer "+aiProperties.getOpenai().getApiKey()).body(body)
                .exchange((request,result)->{
                    if(!result.getStatusCode().is2xxSuccessful())throw new AiProviderFailure(AiProviderFailure.Kind.HTTP_ERROR,true);
                    byte[] bytes=result.getBody().readNBytes(65537);
                    if(bytes.length>65536)throw new IllegalArgumentException("Provider response limit");
                    return objectMapper.reader().with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
                            .with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(bytes);
                });
            if(response==null)throw new IllegalStateException("Empty provider response");
            captureUsage(response);
            if(admission!=null)ledger.complete(admission,lastTokenUsage.get());
            return response;
        }catch(RuntimeException failure){
            if(admission!=null)try{ledger.uncertain(admission);}catch(RuntimeException ignored){/* SENDING remains durable; explicit reconciliation required. */}
            if(failure instanceof AiProviderFailure safe)throw safe;
            for(Throwable cause=failure;cause!=null;cause=cause.getCause())
                if(cause instanceof java.net.SocketTimeoutException||cause instanceof java.net.http.HttpTimeoutException)
                    throw new AiProviderFailure(AiProviderFailure.Kind.TIMEOUT,true);
            throw new AiProviderFailure(AiProviderFailure.Kind.UNKNOWN,true);
        }
    }

    private RestClient restClient() {
        if (testClient != null) return testClient;
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
        int cached=usage.path("input_tokens_details").path("cached_tokens").asInt(0);
        boolean known=inputTokens>=0&&outputTokens>=0&&totalTokens>=0&&cached>=0&&cached<=inputTokens&&usage.has("input_tokens")&&usage.has("output_tokens");
        lastTokenUsage.set(new AiTokenUsage(inputTokens, outputTokens, totalTokens, true,cached,response.path("model").isTextual()?response.path("model").asText():null,known));
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
                "AI 수정 제안", "수정 후 재분석하세요.", null,
                com.securedeploy.rule.model.FalsePositiveRisk.MEDIUM,
                com.securedeploy.rule.model.DetectionConfidence.LOW,
                "AI 응답과 Rule Engine finding 매칭에 실패했습니다.");
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
