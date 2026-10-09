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
public class CisaKevClient {
    public static final String SOURCE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private final RestClient http;
    private final ObjectMapper mapper;
    private final ThreatIntelProperties properties;
    private final Clock clock;
    private Catalog cached;
    private Instant retryAfter = Instant.MIN;

    public CisaKevClient(@Qualifier("threatIntelRestClient") RestClient http, ObjectMapper mapper,
                         ThreatIntelProperties properties, @Qualifier("threatIntelClock") Clock clock) {
        this.http = http; this.mapper = mapper; this.properties = properties; this.clock = clock;
    }

    public synchronized Map<String, KevData> lookup(List<String> cves) {
        if (cves.isEmpty()) return Map.of();
        Instant now = clock.instant();
        boolean fresh = cached != null && cached.fetchedAt().plusSeconds(properties.cacheTtlSeconds()).isAfter(now);
        if (!fresh && !now.isBefore(retryAfter)) {
            try {
                Catalog next = parse(ThreatIntelJson.get(http, mapper, URI.create(SOURCE), 15_000_000));
                if (cached != null && next.releasedAt().isBefore(cached.releasedAt())) {
                    throw new IllegalStateException("Regressed KEV catalog");
                }
                cached = next;
                fresh = true;
            } catch (RuntimeException failure) {
                retryAfter = clock.instant().plusSeconds(properties.failureBackoffSeconds());
            }
        }
        Map<String, KevData> result = new LinkedHashMap<>();
        for (String cve : cves) {
            if (cve == null || !Objects.equals(cve, CveIdentifiers.normalize(cve))) continue;
            if (cached == null) {
                result.put(cve, new KevData(cve, null, null, null, null, null, null, null, UNAVAILABLE, SOURCE, null));
                continue;
            }
            Entry entry = cached.entries().get(cve);
            // A negative result is valid only for a complete, freshly fetched catalog.
            result.put(cve, new KevData(cve, entry != null ? Boolean.TRUE : fresh ? Boolean.FALSE : null,
                    entry == null ? null : entry.dateAdded(), entry == null ? null : entry.requiredAction(),
                    entry == null ? null : entry.dueDate(), entry == null ? null : entry.ransomware(),
                    cached.version(), cached.releasedAt(), fresh ? AVAILABLE : STALE, SOURCE, cached.fetchedAt()));
        }
        return Map.copyOf(result);
    }

    private Catalog parse(JsonNode root) {
        Instant released = Instant.parse(ThreatIntelJson.text(root, "dateReleased", 50, true));
        if (released.isAfter(clock.instant().plusSeconds(300))) throw new IllegalStateException("Future KEV date");
        String version = ThreatIntelJson.text(root, "catalogVersion", 100, false);
        JsonNode rows = root.path("vulnerabilities");
        if (!rows.isArray() || rows.isEmpty() || !root.path("count").isIntegralNumber() || !root.path("count").canConvertToInt()
                || root.path("count").asInt() != rows.size() || rows.size() > 50000) {
            throw new IllegalStateException("Incomplete KEV catalog");
        }
        Map<String, Entry> entries = new HashMap<>();
        for (JsonNode row : rows) {
            String cve = ThreatIntelJson.text(row, "cveID", 32, true);
            if (!cve.equals(CveIdentifiers.normalize(cve)) || entries.containsKey(cve)) {
                throw new IllegalStateException("Invalid KEV identity");
            }
            entries.put(cve, new Entry(date(row, "dateAdded"), ThreatIntelJson.text(row, "requiredAction", 10000, false),
                    date(row, "dueDate"), ThreatIntelJson.text(row, "knownRansomwareCampaignUse", 100, false)));
        }
        return new Catalog(Map.copyOf(entries), version, released, clock.instant());
    }
    private LocalDate date(JsonNode row, String name) {
        String value = ThreatIntelJson.text(row, name, 10, false);
        return value == null ? null : LocalDate.parse(value);
    }
    private record Entry(LocalDate dateAdded, String requiredAction, LocalDate dueDate, String ransomware) { }
    private record Catalog(Map<String, Entry> entries, String version, Instant releasedAt, Instant fetchedAt) { }
}
