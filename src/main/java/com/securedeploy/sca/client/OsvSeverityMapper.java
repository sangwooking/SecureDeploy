package com.securedeploy.sca.client;
import com.fasterxml.jackson.databind.JsonNode;
import com.securedeploy.rule.model.Severity;
import java.util.*;

public class OsvSeverityMapper {
    public record Assessment(Severity severity, Double score, List<String> vectors) { }
    public Assessment map(JsonNode advisory, List<JsonNode> affected) {
        List<String> vectors = new ArrayList<>();
        Double score = null;
        List<JsonNode> sources = new ArrayList<>(affected);
        sources.add(advisory);
        Severity severity = null;
        for (JsonNode source : sources) {
            for (JsonNode entry : source.path("severity")) {
                String raw = entry.path("score").asText();
                if (raw.startsWith("CVSS:")) vectors.add(raw);
                else {
                    Double numeric = numeric(raw);
                    if (numeric != null) score = score == null ? numeric : Math.max(score, numeric);
                }
            }
            Double numeric = numeric(source.path("database_specific").path("cvss").path("score").asText());
            if (numeric != null) score = score == null ? numeric : Math.max(score, numeric);
            String label = source.path("database_specific").path("severity").asText().toUpperCase(Locale.ROOT);
            Severity mapped = switch (label) {
                case "CRITICAL" -> Severity.CRITICAL;
                case "HIGH" -> Severity.HIGH;
                case "MEDIUM", "MODERATE" -> Severity.MEDIUM;
                case "LOW" -> Severity.LOW;
                default -> null;
            };
            if (mapped != null && (severity == null || mapped.ordinal() > severity.ordinal())) severity = mapped;
        }
        if (score != null) severity = score >= 9 ? Severity.CRITICAL : score >= 7 ? Severity.HIGH : score >= 4 ? Severity.MEDIUM : Severity.LOW;
        return new Assessment(severity, score, vectors.stream().distinct().toList());
    }
    private Double numeric(String raw) {
        try { double score = Double.parseDouble(raw); return Double.isFinite(score) && score >= 0 && score <= 10 ? score : null; }
        catch (NumberFormatException ignored) { return null; }
    }
}
