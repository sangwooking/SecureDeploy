package com.securedeploy.threatintel;

import com.securedeploy.threatintel.client.*;
import com.securedeploy.threatintel.config.ThreatIntelProperties;
import com.securedeploy.threatintel.model.*;
import java.time.*;

final class ThreatFixtures {
    static final String CVE = "CVE-2099-0001";
    static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");
    static ThreatIntelProperties properties() { return new ThreatIntelProperties(true, 2, 5, 300, 3600, 60, 2); }
    static EpssData epss(double score, double percentile) {
        return new EpssData(CVE, score, percentile, LocalDate.of(2026, 10, 7), LookupStatus.AVAILABLE, EpssClient.SOURCE, NOW);
    }
    static KevData kev(Boolean known, LookupStatus status) {
        return new KevData(CVE, known, null, "Synthetic test action", null, null, "fixture", NOW, status, CisaKevClient.SOURCE, NOW);
    }
    static String epssJson(String values) {
        return "{\"status\":\"OK\",\"total\":1,\"data\":[{\"cve\":\"" + CVE + "\",\"date\":\"2026-10-07\"," + values + "}]}";
    }
    static String kevJson() {
        return "{\"catalogVersion\":\"fixture\",\"dateReleased\":\"2026-10-07T11:00:00Z\",\"count\":1,\"vulnerabilities\":[{\"cveID\":\"" + CVE + "\"}]}";
    }
    static class MutableClock extends Clock {
        Instant now = NOW;
        void advance(Duration duration) { now = now.plus(duration); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
