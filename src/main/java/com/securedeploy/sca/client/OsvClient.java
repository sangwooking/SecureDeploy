package com.securedeploy.sca.client;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class OsvClient implements VulnerabilityDataSource {
    private final RestClient http;
    private final ObjectMapper mapper;
    private final ScaProperties properties;
    private final OsvAdvisoryMapper advisoryMapper = new OsvAdvisoryMapper();

    public OsvClient(@Qualifier("osvRestClient") RestClient http, ObjectMapper mapper, ScaProperties properties) {
        this.http = http;
        this.mapper = mapper;
        this.properties = properties;
    }

    @Override
    public LookupResult lookup(List<DependencyComponent> components) {
        Map<String, List<DependencyComponent>> groups = new LinkedHashMap<>();
        components.stream().filter(c -> c.versionResolution() == VersionResolution.EXACT)
                .forEach(c -> groups.computeIfAbsent(c.identity(), k -> new ArrayList<>()).add(c));
        List<String> warnings = new ArrayList<>();
        List<DependencyComponent> queries = groups.values().stream().map(list -> list.get(0))
                .limit(properties.maxQueries()).toList();
        if (groups.size() > queries.size()) warnings.add("OSV 패키지 조회 상한으로 일부 의존성은 조회하지 못했습니다.");
        Map<String, Set<String>> hits = new LinkedHashMap<>();
        Set<String> completed = new HashSet<>();
        Budget budget = new Budget(properties.budgetSeconds());
        try {
            for (int start = 0; start < queries.size(); start += 100) {
                List<Pending> pending = queries.subList(start, Math.min(start + 100, queries.size())).stream()
                        .map(c -> new Pending(c, null)).toList();
                while (!pending.isEmpty()) {
                    List<Map<String, Object>> payload = new ArrayList<>();
                    for (Pending p : pending) {
                        Map<String, Object> query = new LinkedHashMap<>();
                        query.put("package", Map.of("ecosystem", p.component().ecosystem().osvName(), "name", p.component().packageName()));
                        query.put("version", p.component().version());
                        if (p.token() != null) query.put("page_token", p.token());
                        payload.add(query);
                    }
                    JsonNode response = request(http.post().uri("/v1/querybatch")
                            .contentType(MediaType.APPLICATION_JSON).body(Map.of("queries", payload)), budget);
                    JsonNode results = response.path("results");
                    if (!results.isArray() || results.size() != pending.size()) throw new IllegalStateException("Invalid OSV batch");
                    List<Pending> next = new ArrayList<>();
                    for (int i = 0; i < pending.size(); i++) {
                        Pending p = pending.get(i);
                        JsonNode result = results.get(i);
                        if (!result.isObject() || result.has("error")
                                || (result.has("vulns") && !result.path("vulns").isArray())) throw new IllegalStateException("Invalid OSV result");
                        Set<String> ids = hits.computeIfAbsent(p.component().identity(), k -> new LinkedHashSet<>());
                        for (JsonNode vuln : result.path("vulns")) {
                            String id = vuln.path("id").asText();
                            if (!id.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")) throw new IllegalStateException("Invalid advisory id");
                            if (ids.size() >= 500) throw new IllegalStateException("Advisory limit");
                            ids.add(id);
                        }
                        String token = result.path("next_page_token").asText();
                        if (token.isEmpty()) completed.add(p.component().identity());
                        else next.add(new Pending(p.component(), token));
                    }
                    pending = next;
                }
            }
        } catch (RuntimeException exception) {
            warnings.add("OSV 조회가 실패하거나 제한 시간에 도달했습니다. 미조회 의존성을 안전한 것으로 판단하지 마세요.");
        }
        Map<String, JsonNode> cache = new HashMap<>();
        List<DependencyVulnerability> findings = new ArrayList<>();
        boolean detailsUnavailable = false;
        for (var entry : hits.entrySet()) {
            DependencyComponent component = groups.get(entry.getKey()).get(0);
            List<String> paths = groups.get(entry.getKey()).stream().map(DependencyComponent::sourceFile).distinct().sorted().toList();
            for (String id : entry.getValue()) {
                JsonNode data = cache.get(id);
                if (data == null && !detailsUnavailable) {
                    try {
                        if (cache.size() >= properties.maxAdvisories()) throw new IllegalStateException("Detail limit");
                        data = request(http.get().uri("/v1/vulns/{id}", id), budget);
                        if (!id.equals(data.path("id").asText())) throw new IllegalStateException("Invalid advisory");
                        cache.put(id, data);
                    } catch (RuntimeException exception) {
                        detailsUnavailable = true;
                        warnings.add("일부 OSV advisory 상세를 가져오지 못했습니다. 확인된 ID는 보존하며 심각도/수정 버전은 미확인으로 표시합니다.");
                    }
                }
                if (data == null) data = JsonNodeFactory.instance.objectNode();
                if (data.hasNonNull("withdrawn")) continue;
                if (findings.size() >= 2000) {
                    warnings.add("SCA 결과 2000건 제한으로 일부 결과를 생략했습니다.");
                    return new LookupResult(findings, completed, true, warnings);
                }
                findings.add(advisoryMapper.map(id, data, component, paths));
            }
        }
        return new LookupResult(findings, completed, !warnings.isEmpty(), warnings);
    }

    private JsonNode request(RestClient.RequestHeadersSpec<?> request, Budget budget) {
        budget.check();
        return request.exchange((req, response) -> {
            if (!response.getStatusCode().is2xxSuccessful()) throw new IllegalStateException("OSV unavailable");
            byte[] bytes = response.getBody().readNBytes(2_000_001);
            if (bytes.length > 2_000_000) throw new IllegalStateException("OSV response limit");
            JsonNode data = mapper.readTree(bytes);
            if (data == null || !data.isObject()) throw new IllegalStateException("Invalid OSV JSON");
            return data;
        });
    }
    private record Pending(DependencyComponent component, String token) { }
    private static class Budget {
        private final long deadline;
        private int requests;
        Budget(int seconds) { deadline = System.nanoTime() + seconds * 1_000_000_000L; }
        void check() {
            if (++requests > 50 || System.nanoTime() > deadline) throw new IllegalStateException("OSV budget exceeded");
        }
    }
}
