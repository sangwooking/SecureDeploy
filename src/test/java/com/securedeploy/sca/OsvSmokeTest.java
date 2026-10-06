package com.securedeploy.sca;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.sca.client.OsvClient;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.ScaEcosystem;
import com.securedeploy.sca.parser.VersionClassifier;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.*;

@EnabledIfEnvironmentVariable(named = "SCA_OSV_SMOKE", matches = "true")
class OsvSmokeTest {
    @Test void knownLog4jAdvisoryIsReturnedByLiveOsv() {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000);
        factory.setReadTimeout(5000);
        var http = RestClient.builder().baseUrl("https://api.osv.dev").requestFactory(factory).build();
        var client = new OsvClient(http, new ObjectMapper(), new ScaProperties(true, 5, 30, 10, 100));
        var component = VersionClassifier.component(ScaEcosystem.MAVEN, "org.apache.logging.log4j:log4j-core",
                "2.14.1", "runtime", true, "fixture/pom.xml", 0);
        var result = client.lookup(List.of(component));
        assertThat(result.incomplete()).isFalse();
        assertThat(result.findings()).anyMatch(v -> v.aliases().contains("CVE-2021-44228"));
    }
}
