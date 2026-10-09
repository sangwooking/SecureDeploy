package com.securedeploy.threatintel.service;

import com.securedeploy.sca.model.ScaResult;
import com.securedeploy.threatintel.client.*;
import com.securedeploy.threatintel.config.ThreatIntelProperties;
import com.securedeploy.threatintel.model.*;
import java.time.Clock;
import java.util.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import static com.securedeploy.threatintel.model.LookupStatus.*;
import static com.securedeploy.threatintel.model.ThreatIntelligenceSnapshot.Status.*;

@Service
public class ThreatIntelligenceService {
    private final EpssClient epss;
    private final CisaKevClient kev;
    private final ThreatIntelProperties properties;
    private final Clock clock;
    public ThreatIntelligenceService(EpssClient epss, CisaKevClient kev, ThreatIntelProperties properties,
                                      @Qualifier("threatIntelClock") Clock clock) {
        this.epss = epss; this.kev = kev; this.properties = properties; this.clock = clock;
    }

    public ThreatIntelligenceSnapshot enrich(ScaResult sca) {
        List<String> ids = sca == null ? List.of() : sca.dependencyVulnerabilities().stream()
                .flatMap(f -> CveIdentifiers.from(f).stream()).distinct().sorted().toList();
        int withoutCve = sca == null ? 0 : (int) sca.dependencyVulnerabilities().stream()
                .filter(f -> CveIdentifiers.from(f).isEmpty()).count();
        String id = UUID.randomUUID().toString();
        if (ids.isEmpty()) return new ThreatIntelligenceSnapshot(id, clock.instant(), NOT_APPLICABLE, 0, withoutCve, Map.of(), List.of());
        if (!properties.enabled()) return new ThreatIntelligenceSnapshot(id, clock.instant(), DISABLED, ids.size(), withoutCve, Map.of(),
                List.of("Threat Intelligence 조회가 비활성화되어 CVE의 악용 정보를 확인하지 못했습니다."));
        List<String> requested = ids.stream().limit(properties.maxCves()).toList();
        Map<String, EpssData> epssResult;
        Map<String, KevData> kevResult;
        // Keep both source failures outside the review transaction and independent of each other.
        try { epssResult = epss.lookup(requested); } catch (RuntimeException failure) { epssResult = Map.of(); }
        try { kevResult = kev.lookup(requested); } catch (RuntimeException failure) { kevResult = Map.of(); }
        Map<String, ThreatIntelligence> data = new TreeMap<>();
        List<String> warnings = new ArrayList<>();
        if (requested.size() < ids.size()) warnings.add("Threat Intelligence CVE 조회 상한에 도달했습니다. 생략된 CVE는 미확인입니다.");
        for (String cve : ids) {
            LookupStatus missing = requested.contains(cve) ? LookupStatus.UNAVAILABLE : NOT_REQUESTED;
            EpssData e = epssResult.getOrDefault(cve, new EpssData(cve, null, null, null, missing, EpssClient.SOURCE, null));
            KevData k = kevResult.getOrDefault(cve, new KevData(cve, null, null, null, null, null, null, null, missing, CisaKevClient.SOURCE, null));
            data.put(cve, new ThreatIntelligence(cve, e, k));
        }
        boolean all = data.values().stream().allMatch(t -> t.epss().status() == AVAILABLE && t.kev().status() == AVAILABLE);
        boolean stale = data.values().stream().anyMatch(t -> t.epss().status() == LookupStatus.STALE || t.kev().status() == LookupStatus.STALE);
        boolean any = data.values().stream().anyMatch(t -> t.epss().status() == AVAILABLE || t.kev().status() == AVAILABLE);
        if (data.values().stream().anyMatch(t -> t.epss().status() != AVAILABLE)) warnings.add("FIRST EPSS에 미조회·미수록 또는 오래된 데이터가 있습니다. 낮은 악용 가능성으로 해석하지 마세요.");
        if (data.values().stream().anyMatch(t -> t.kev().status() != AVAILABLE)) warnings.add("CISA KEV 최신 조회가 완료되지 않았습니다. 미확인 결과는 악용 사례가 없다는 뜻이 아닙니다.");
        var status = all ? COMPLETE : stale ? ThreatIntelligenceSnapshot.Status.STALE : any ? PARTIAL : ThreatIntelligenceSnapshot.Status.UNAVAILABLE;
        return new ThreatIntelligenceSnapshot(id, clock.instant(), status, ids.size(), withoutCve, Map.copyOf(data), List.copyOf(warnings));
    }
}
