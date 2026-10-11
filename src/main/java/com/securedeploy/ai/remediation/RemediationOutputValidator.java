package com.securedeploy.ai.remediation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.math.BigDecimal;
import static com.securedeploy.ai.remediation.RemediationValidationException.Reason.*;

public final class RemediationOutputValidator {
    private static final List<String> TEXT_FIELDS = List.of("summary", "whyItMatters", "recommendedAction", "codeExample", "configurationExample", "caution");
    private static final Pattern VERSION = Pattern.compile("(?<![\\d.])\\d+\\.\\d+(?:\\.\\d+)*(?:[-+][a-zA-Z0-9.-]+)?");
    private static final Pattern THREAT_METRIC = Pattern.compile(
            "(?i)\\b(CVSS|EPSS)(?:\\s+(?:score|percentile|점수|백분위|확률))?\\s*[:=]?\\s*(\\d+(?:\\.\\d+)?)(%)?(?![\\w.])");
    private RemediationOutputValidator() { }

    public static Map<String, Object> schema(List<RemediationContext> contexts) {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("findingId", Map.of("type", "string", "enum", contexts.stream().map(RemediationContext::findingId).toList()));
        TEXT_FIELDS.forEach(field -> props.put(field, Map.of("type", "string")));
        props.put("verificationSteps", Map.of("type", "array", "items", Map.of("type", "string")));
        props.put("remediationConfidence", Map.of("type", "string", "enum", List.of("HIGH", "MEDIUM", "LOW")));
        var item = Map.of("type", "object", "additionalProperties", false, "required", List.copyOf(props.keySet()), "properties", props);
        return Map.of("type", "object", "additionalProperties", false, "required", List.of("findings"),
                "properties", Map.of("findings", Map.of("type", "array", "items", item)));
    }

    public static Map<String, RemediationContent> parse(JsonNode root, List<RemediationContext> contexts, ObjectMapper mapper) {
        if (!root.isObject() || root.size() != 1 || !root.path("findings").isArray()
                || root.path("findings").size() != contexts.size()) throw invalid(INVALID_SCHEMA);
        Map<String, RemediationContent> result = new LinkedHashMap<>();
        for (var node : root.path("findings")) {
            if (node.size() != 9 || !node.path("findingId").isTextual()) throw invalid(INVALID_SCHEMA);
            var context = contexts.stream().filter(c -> c.findingId().equals(node.path("findingId").asText())).findFirst().orElseThrow(() -> invalid(INVALID_FINDING_ID));
            for (var field : TEXT_FIELDS) if (!node.path(field).isTextual() || node.path(field).asText().length() > 4_000) throw invalid(INVALID_SCHEMA);
            if (!node.path("verificationSteps").isArray()) throw invalid(INVALID_SCHEMA);
            for (var step : node.path("verificationSteps")) if (!step.isTextual()) throw invalid(INVALID_SCHEMA);
            var copy = node.deepCopy();
            ((com.fasterxml.jackson.databind.node.ObjectNode) copy).remove("findingId");
            try {
                RemediationContent content = mapper.treeToValue(copy, RemediationContent.class);
                validate(content, context);
                if (result.put(context.findingId(), content) != null) throw invalid(INVALID_FINDING_ID);
            } catch (com.fasterxml.jackson.core.JsonProcessingException exception) { throw invalid(INVALID_SCHEMA); }
        }
        return result;
    }

    public static void validate(RemediationContent value, RemediationContext context) {
        if (value == null || value.summary() == null || value.summary().isBlank()
                || value.whyItMatters() == null || value.whyItMatters().isBlank()
                || value.recommendedAction() == null || value.recommendedAction().isBlank()
                || value.remediationConfidence() == null || value.verificationSteps() == null
                || value.verificationSteps().isEmpty() || value.verificationSteps().size() > 8
                || value.verificationSteps().stream().anyMatch(s -> s == null || s.isBlank() || s.length() > 1_000)) throw invalid(INVALID_CONTENT);
        if (context.dependency() != null) {
            Set<String> versions = new HashSet<>(context.dependency().fixedVersions());
            versions.add(context.dependency().installedVersion());
            // Exempt only explicitly labelled, input-backed metrics. A package version numerically
            // equal to CVSS is still rejected unless it is a saved package version.
            String text = THREAT_METRIC.matcher(value.toString()).replaceAll(match ->
                    supportedMetric(match.group(), match.group(1), match.group(2), match.group(3), context.dependency())
                            ? "[known threat metric]" : Matcher.quoteReplacement(match.group()));
            var matches = VERSION.matcher(text);
            while (matches.find()) if (!versions.contains(matches.group())) throw invalid(UNSUPPORTED_VERSION_REFERENCE);
        }
    }
    private static boolean supportedMetric(String label, String type, String number, String percent,
                                           RemediationContext.DependencyContext context) {
        BigDecimal actual = new BigDecimal(number);
        boolean isPercent = percent != null;
        if (type.equalsIgnoreCase("CVSS")) return !isPercent && equalsMetric(actual, context.cvss(), false);
        boolean percentile = label.toLowerCase(Locale.ROOT).contains("percentile") || label.contains("백분위");
        return context.threatIntelligence().stream().anyMatch(signal -> equalsMetric(actual,
                percentile ? signal.percentile() : signal.epss(), isPercent));
    }
    private static boolean equalsMetric(BigDecimal actual, Double expected, boolean percent) {
        if (expected == null || !Double.isFinite(expected)) return false;
        BigDecimal value = BigDecimal.valueOf(expected);
        return actual.compareTo(percent ? value.movePointRight(2) : value) == 0;
    }
    private static RemediationValidationException invalid(RemediationValidationException.Reason reason) {
        return new RemediationValidationException(reason);
    }
}
