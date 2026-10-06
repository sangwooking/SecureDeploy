package com.securedeploy.sca.client;
import com.fasterxml.jackson.databind.JsonNode;
import com.securedeploy.sca.model.*;
import java.util.*;
import java.net.URI;

public class OsvAdvisoryMapper {
    private final OsvSeverityMapper severityMapper = new OsvSeverityMapper();
    public DependencyVulnerability map(String id, JsonNode data, DependencyComponent component, List<String> paths) {
        List<JsonNode> affected = new ArrayList<>();
        data.path("affected").forEach(a -> {
            if (component.ecosystem().osvName().equals(a.path("package").path("ecosystem").asText())
                    && component.packageName().equals(a.path("package").path("name").asText())) affected.add(a);
        });
        var severity = severityMapper.map(data, affected);
        Set<String> fixes = new LinkedHashSet<>();
        for (JsonNode a : affected) for (JsonNode range : a.path("ranges")) {
            if ("GIT".equals(range.path("type").asText())) continue;
            for (JsonNode event : range.path("events")) if (event.hasNonNull("fixed")) fixes.add(event.path("fixed").asText());
        }
        List<String> references = new ArrayList<>();
        for (JsonNode ref : data.path("references")) {
            String url = ref.path("url").asText();
            try {
                URI uri = URI.create(url);
                if (("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())) && uri.getHost() != null && uri.getUserInfo() == null) references.add(url);
            } catch (IllegalArgumentException ignored) { }
        }
        List<String> aliases = new ArrayList<>();
        data.path("aliases").forEach(a -> { if (a.isTextual()) aliases.add(a.asText()); });
        return new DependencyVulnerability(component.ecosystem(), component.packageName(), component.version(),
                id, aliases, nullable(data, "summary"), severity.severity(), severity.score(), severity.vectors(),
                List.copyOf(fixes), nullable(data, "published"), nullable(data, "modified"), references, paths);
    }
    private String nullable(JsonNode node, String field) { return node.hasNonNull(field) ? node.get(field).asText() : null; }
}
