package com.securedeploy.sca;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.sca.client.OsvClient;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.ScaEcosystem;
import com.securedeploy.sca.parser.VersionClassifier;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.*;

@EnabledIfEnvironmentVariable(named = "PYTHON_OSV_SMOKE", matches = "true")
class PythonOsvSmokeTest {
    @Test void exactPublicPyPiVersionUsesExistingOsvClientWithBoundedRequests() {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000); factory.setReadTimeout(5000);
        var requests = new AtomicInteger();
        var http = RestClient.builder().baseUrl("https://api.osv.dev").requestFactory(factory)
                .requestInterceptor((request, body, execution) -> {
                    if (requests.incrementAndGet() > 4) throw new java.io.IOException("Smoke request budget");
                    return execution.execute(request, body);
                }).build();
        var client = new OsvClient(http, new ObjectMapper(), new ScaProperties(true, 5, 20, 1, 3));
        var component = VersionClassifier.component(ScaEcosystem.PYPI, "urllib3", "1.26.17", "DECLARATION", null, "requirements.txt", 1);
        var result = client.lookup(List.of(component));
        assertThat(result.analyzedIdentities()).contains(component.identity());
        assertThat(result.findings()).anyMatch(f -> f.ecosystem() == ScaEcosystem.PYPI && !f.fixedVersions().isEmpty()
                && f.affectedRanges() != null && !f.affectedRanges().isEmpty());
        assertThat(requests.get()).isBetween(2, 4);
        // A deliberately small detail budget can leave additional advisories unresolved.
        System.out.printf("PyPI smoke requests=%d findings=%d incomplete=%s%n", requests.get(), result.findings().size(), result.incomplete());
    }
}
