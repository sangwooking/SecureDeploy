package com.securedeploy.threatintel;

import com.securedeploy.threatintel.client.*;
import com.securedeploy.threatintel.model.LookupStatus;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest
@EnabledIfEnvironmentVariable(named = "THREAT_INTEL_SMOKE", matches = "true")
class ThreatIntelSmokeTest {
    @Autowired EpssClient epss;
    @Autowired CisaKevClient kev;
    @Test void officialSourcesReturnLog4ShellEvidence() {
        String cve = "CVE-2021-44228";
        var e = epss.lookup(List.of(cve)).get(cve);
        var k = kev.lookup(List.of(cve)).get(cve);
        assertThat(e.status()).isEqualTo(LookupStatus.AVAILABLE);
        assertThat(e.date()).isNotNull();
        assertThat(k.status()).isEqualTo(LookupStatus.AVAILABLE);
        assertThat(k.knownExploited()).isTrue();
        System.out.println("Official threat smoke: " + cve + ", EPSS=" + e.score() + ", percentile=" + e.percentile()
                + ", date=" + e.date() + ", KEV=" + k.knownExploited() + ", catalog=" + k.catalogVersion());
    }
}
