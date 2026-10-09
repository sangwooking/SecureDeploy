package com.securedeploy.threatintel;

import com.securedeploy.threatintel.client.*;
import com.securedeploy.threatintel.config.ThreatIntelProperties;
import com.securedeploy.threatintel.model.*;
import com.securedeploy.threatintel.service.ThreatIntelligenceService;
import com.securedeploy.rule.model.Severity;
import com.securedeploy.sca.model.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import static org.assertj.core.api.Assertions.*;
import static com.securedeploy.threatintel.ThreatFixtures.*;

class ThreatIntelligenceServiceTest {
    EpssClient epss = mock(EpssClient.class);
    CisaKevClient kev = mock(CisaKevClient.class);
    ThreatIntelligenceService service = new ThreatIntelligenceService(epss, kev, properties(), new MutableClock());
    ScaResult sca(List<String> aliases) {
        var dep = new DependencyVulnerability(ScaEcosystem.NPM, "fixture", "1.0.0", "OSV-fixture", aliases,
                "Synthetic", Severity.HIGH, null, List.of(), List.of(), null, null, List.of(), List.of("package.json"));
        return new ScaResult(1, ScaResult.Status.COMPLETE, NOW, new ScaResult.Summary(1,1,0,1,1,Map.of()), List.of(), List.of(dep), List.of());
    }
    @Test void noCveOrMalformedAliasNeverQueriesExternalSources() {
        var snapshot = service.enrich(sca(List.of("GHSA-fixture", "prefix-CVE-2099-0001", "CVE-2099-0001&query=all")));
        assertThat(snapshot.status()).isEqualTo(ThreatIntelligenceSnapshot.Status.NOT_APPLICABLE);
        assertThat(snapshot.findingsWithoutCve()).isEqualTo(1);
        verifyNoInteractions(epss, kev);
    }
    @Test void independentlyFailedSourcesRemainUnavailableWithoutThrowing() {
        when(epss.lookup(anyList())).thenThrow(new IllegalStateException("synthetic timeout"));
        when(kev.lookup(anyList())).thenThrow(new IllegalStateException("synthetic invalid JSON"));
        var snapshot = service.enrich(sca(List.of(CVE)));
        assertThat(snapshot.status()).isEqualTo(ThreatIntelligenceSnapshot.Status.UNAVAILABLE);
        assertThat(snapshot.cves().get(CVE).kev().knownExploited()).isNull();
        assertThat(snapshot.warnings()).hasSize(2);
    }
    @Test void epssFailureDoesNotDiscardKevPositive() {
        when(epss.lookup(anyList())).thenThrow(new IllegalStateException("synthetic timeout"));
        when(kev.lookup(anyList())).thenReturn(Map.of(CVE, kev(true, LookupStatus.AVAILABLE)));
        var snapshot = service.enrich(sca(List.of(CVE)));
        assertThat(snapshot.status()).isEqualTo(ThreatIntelligenceSnapshot.Status.PARTIAL);
        assertThat(snapshot.cves().get(CVE).kev().knownExploited()).isTrue();
    }
    @Test void freshScanHasNewSnapshotIdEvenWhenSourceValuesAreCached() {
        when(epss.lookup(anyList())).thenReturn(Map.of(CVE, epss(.8, .98)));
        when(kev.lookup(anyList())).thenReturn(Map.of(CVE, kev(false, LookupStatus.AVAILABLE)));
        var first = service.enrich(sca(List.of(CVE, CVE.toLowerCase(Locale.ROOT))));
        var second = service.enrich(sca(List.of(CVE)));
        assertThat(first.status()).isEqualTo(ThreatIntelligenceSnapshot.Status.COMPLETE);
        assertThat(first.requestedCves()).isEqualTo(1);
        assertThat(first.snapshotId()).isNotEqualTo(second.snapshotId());
        assertThat(first.cves()).isEqualTo(second.cves());
        verify(epss, times(2)).lookup(List.of(CVE));
    }
    @Test void maxCveLimitIsExplicitNotSilentlyComplete() {
        var restricted = new ThreatIntelligenceService(epss, kev, new ThreatIntelProperties(true,2,5,1,60,60,2), new MutableClock());
        when(epss.lookup(List.of(CVE))).thenReturn(Map.of(CVE, epss(.1,.2)));
        when(kev.lookup(List.of(CVE))).thenReturn(Map.of(CVE, kev(false,LookupStatus.AVAILABLE)));
        var result = restricted.enrich(sca(List.of(CVE,"CVE-2099-0002")));
        assertThat(result.status()).isEqualTo(ThreatIntelligenceSnapshot.Status.PARTIAL);
        assertThat(result.cves().get("CVE-2099-0002").epss().status()).isEqualTo(LookupStatus.NOT_REQUESTED);
        verify(epss).lookup(List.of(CVE));
        verify(kev).lookup(List.of(CVE));
    }
}
