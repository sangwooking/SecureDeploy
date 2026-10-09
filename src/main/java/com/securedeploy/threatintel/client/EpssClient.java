package com.securedeploy.threatintel.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.threatintel.config.ThreatIntelProperties;
import com.securedeploy.threatintel.model.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import static com.securedeploy.threatintel.model.LookupStatus.*;

@Component
public class EpssClient {
    public static final String SOURCE = "https://api.first.org/data/v1/epss";
    private final RestClient http;
    private final ObjectMapper mapper;
    private final ThreatIntelProperties properties;
    private final Clock clock;
    private final Map<String, EpssData> cache = new LinkedHashMap<>();
    private Instant retryAfter = Instant.MIN;

    public EpssClient(@Qualifier("threatIntelRestClient") RestClient http, ObjectMapper mapper,
                      ThreatIntelProperties properties, @Qualifier("threatIntelClock") Clock clock) {
        this.http = http; this.mapper = mapper; this.properties = properties; this.clock = clock;
    }

    public synchronized Map<String, EpssData> lookup(List<String> cves) {
        Instant now = clock.instant();
        Map<String, EpssData> results = new LinkedHashMap<>();
        List<String> pending = new ArrayList<>();
        for (String cve : cves.stream().distinct().toList()) {
            if (cve == null || !Objects.equals(cve, CveIdentifiers.normalize(cve))) continue;
            EpssData cached = cache.get(cve);
            if (cached != null && cached.fetchedAt().plusSeconds(properties.cacheTtlSeconds()).isAfter(now)
                    && cached.fetchedAt().atZone(ZoneOffset.UTC).toLocalDate().equals(LocalDate.now(clock))) {
                results.put(cve, freshStatus(cached));
            } else pending.add(cve);
        }
        long deadline = System.nanoTime() + properties.budgetSeconds() * 1_000_000_000L;
        for (List<String> batch : batches(pending)) {
            try {
                if (now.isBefore(retryAfter) || System.nanoTime() > deadline) throw new IllegalStateException("EPSS budget/backoff");
                URI uri = URI.create(SOURCE + "?cve=" + String.join(",", batch) + "&limit=" + batch.size());
                JsonNode root = ThreatIntelJson.get(http, mapper, uri, 1_000_000);
                JsonNode data = root.path("data");
                if (!"OK".equals(root.path("status").asText()) || !data.isArray()
                        || !root.path("total").isIntegralNumber() || !root.path("total").canConvertToInt()
                        || root.path("total").asInt() != data.size()
                        || data.size() > batch.size()) throw new IllegalStateException("Incomplete EPSS batch");
                Map<String, EpssData> parsed = new HashMap<>();
                for (JsonNode row : data) {
                    String cve = ThreatIntelJson.text(row, "cve", 32, true);
                    LocalDate date = LocalDate.parse(ThreatIntelJson.text(row, "date", 10, true));
                    if (!batch.contains(cve) || parsed.containsKey(cve) || date.isAfter(LocalDate.now(clock))) {
                        throw new IllegalStateException("Invalid EPSS identity/date");
                    }
                    parsed.put(cve, new EpssData(cve, probability(row.get("epss")), probability(row.get("percentile")),
                            date, AVAILABLE, SOURCE, clock.instant()));
                }
                for (String cve : batch) {
                    EpssData value = parsed.getOrDefault(cve, new EpssData(cve, null, null, null, NOT_FOUND, SOURCE, clock.instant()));
                    cache.put(cve, value);
                    results.put(cve, freshStatus(value));
                }
                while (cache.size() > 5000) cache.remove(cache.keySet().iterator().next());
            } catch (RuntimeException failure) {
                retryAfter = clock.instant().plusSeconds(properties.failureBackoffSeconds());
                for (String cve : batch) {
                    EpssData old = cache.get(cve);
                    results.put(cve, old != null && old.score() != null ? old.withStatus(STALE)
                            : new EpssData(cve, null, null, null, UNAVAILABLE, SOURCE, null));
                }
            }
        }
        return Map.copyOf(results);
    }

    private EpssData freshStatus(EpssData value) {
        return value.date() != null && value.date().isBefore(LocalDate.now(clock).minusDays(properties.epssMaxAgeDays()))
                ? value.withStatus(STALE) : value;
    }
    private double probability(JsonNode value) {
        if (value == null || (!value.isTextual() && !value.isNumber()) || value.asText().length() > 40) {
            throw new IllegalStateException("Missing EPSS probability");
        }
        double result = Double.parseDouble(value.asText());
        if (!Double.isFinite(result) || result < 0 || result > 1) throw new IllegalStateException("Invalid EPSS probability");
        return result;
    }
    // FIRST accepts at most 2,000 CVE-query characters including commas; also cap response rows.
    static List<List<String>> batches(List<String> ids) {
        List<List<String>> batches = new ArrayList<>();
        List<String> current = new ArrayList<>();
        int length = 0;
        for (String id : ids) {
            if (!current.isEmpty() && (length + id.length() + 1 > 1900 || current.size() >= 100)) {
                batches.add(List.copyOf(current)); current.clear(); length = 0;
            }
            length += id.length() + (current.isEmpty() ? 0 : 1);
            current.add(id);
        }
        if (!current.isEmpty()) batches.add(List.copyOf(current));
        return batches;
    }
}
