package com.securedeploy.sca;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.sca.client.*;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.VersionClassifier;
import java.net.SocketTimeoutException;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.http.*;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class OsvClientTest {
    private MockRestServiceServer server;
    private OsvClient client;
    private final ObjectMapper mapper = new ObjectMapper();
    @BeforeEach void setup() {
        var builder = RestClient.builder().baseUrl("https://api.osv.dev");
        server = MockRestServiceServer.bindTo(builder).build();
        client = new OsvClient(builder.build(), mapper, new ScaProperties(true, 1, 10, 500, 100));
    }
    private DependencyComponent dependency(ScaEcosystem ecosystem, String name, String version, String file) {
        return VersionClassifier.component(ecosystem, name, version, "dependencies", true, file, 1);
    }
    @Test void batchesExactVersionsUsesMavenCoordinatesAndPreservesAllLocations() {
        var maven = dependency(ScaEcosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1", "pom.xml");
        var duplicate = dependency(ScaEcosystem.MAVEN, maven.packageName(), "2.14.1", "sub/pom.xml");
        var safe = dependency(ScaEcosystem.NPM, "lodash", "4.17.21", "package-lock.json");
        var range = dependency(ScaEcosystem.NPM, "lodash", "^4.17.0", "package.json");
        server.expect(requestTo("https://api.osv.dev/v1/querybatch")).andExpect(method(HttpMethod.POST))
                .andExpect(content().json("""
                    {"queries":[
                      {"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"version":"2.14.1"},
                      {"package":{"ecosystem":"npm","name":"lodash"},"version":"4.17.21"}
                    ]}
                    """))
                .andRespond(withSuccess("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-fixture-1\"}]},{}]}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.osv.dev/v1/vulns/GHSA-fixture-1")).andRespond(withSuccess("""
            {"id":"GHSA-fixture-1","aliases":["CVE-2099-0001"],"summary":"Offline fixture",
             "severity":[{"type":"CVSS_V3","score":"9.8"}],
             "affected":[
               {"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.17.1"}]}]},
               {"package":{"ecosystem":"npm","name":"different-package"},
                "ranges":[{"events":[{"fixed":"99.0.0"}]}]}],
             "references":[{"url":"https://example.invalid/advisory"},{"url":"javascript:alert(1)"},{"url":"/relative"}]}
            """, MediaType.APPLICATION_JSON));
        var result = client.lookup(List.of(maven, duplicate, safe, range));
        assertThat(result.incomplete()).isFalse();
        assertThat(result.analyzedIdentities()).hasSize(2);
        assertThat(result.findings()).hasSize(1);
        var finding = result.findings().get(0);
        assertThat(finding.sourceFiles()).containsExactly("pom.xml", "sub/pom.xml");
        assertThat(finding.severity().name()).isEqualTo("CRITICAL");
        assertThat(finding.fixedVersions()).containsExactly("2.17.1");
        assertThat(finding.referenceUrls()).containsExactly("https://example.invalid/advisory");
        server.verify();
    }
    @Test void followsPerQueryPaginationAndCachesAdvisoryDetails() {
        var first = dependency(ScaEcosystem.NPM, "lodash", "4.17.10", "package-lock.json");
        var second = dependency(ScaEcosystem.NPM, "lodash", "4.17.11", "other/package-lock.json");
        server.expect(requestTo("https://api.osv.dev/v1/querybatch")).andRespond(withSuccess("""
            {"results":[{"vulns":[{"id":"GHSA-fixture-1"}],"next_page_token":"page2"},
                        {"vulns":[{"id":"GHSA-fixture-1"}]}]}
            """, MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.osv.dev/v1/querybatch"))
                .andExpect(content().json("""
                    {"queries":[{"package":{"ecosystem":"npm","name":"lodash"},"version":"4.17.10","page_token":"page2"}]}
                    """))
                .andRespond(withSuccess("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-fixture-1\"}]}]}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.osv.dev/v1/vulns/GHSA-fixture-1"))
                .andRespond(withSuccess("{\"id\":\"GHSA-fixture-1\",\"database_specific\":{\"severity\":\"MODERATE\"}}", MediaType.APPLICATION_JSON));
        var result = client.lookup(List.of(first, second));
        assertThat(result.findings()).hasSize(2);
        assertThat(result.findings()).allMatch(f -> f.severity().name().equals("MEDIUM"));
        assertThat(result.incomplete()).isFalse();
        server.verify();
    }
    @Test void timeoutDoesNotPretendTheDependencyIsSafe() {
        server.expect(requestTo("https://api.osv.dev/v1/querybatch")).andRespond(withException(new SocketTimeoutException()));
        var result = client.lookup(List.of(dependency(ScaEcosystem.NPM, "lodash", "4.17.10", "package.json")));
        assertThat(result.incomplete()).isTrue();
        assertThat(result.analyzedIdentities()).isEmpty();
        assertThat(result.warnings()).isNotEmpty();
        server.verify();
    }
    @Test void malformedJsonAndRateLimitRemainPartial() {
        server.expect(requestTo("https://api.osv.dev/v1/querybatch"))
                .andRespond(withSuccess("{malformed", MediaType.APPLICATION_JSON));
        assertThat(client.lookup(List.of(dependency(ScaEcosystem.NPM, "lodash", "4.17.10", "package.json"))).incomplete()).isTrue();
        server.verify();
    }
    @Test void detailFailurePreservesKnownIdWithoutInventingSeverity() {
        server.expect(requestTo("https://api.osv.dev/v1/querybatch"))
                .andRespond(withSuccess("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-fixture-1\"}]}]}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.osv.dev/v1/vulns/GHSA-fixture-1"))
                .andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));
        var result = client.lookup(List.of(dependency(ScaEcosystem.NPM, "lodash", "4.17.10", "package.json")));
        assertThat(result.incomplete()).isTrue();
        assertThat(result.findings()).hasSize(1);
        assertThat(result.findings().get(0).severity()).isNull();
        assertThat(result.findings().get(0).osvId()).isEqualTo("GHSA-fixture-1");
    }
    @Test void vectorWithoutNumericScoreIsPreservedAndNeverInvented() throws Exception {
        var mapped = new OsvSeverityMapper().map(mapper.readTree("""
            {"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
            """), List.of());
        assertThat(mapped.vectors()).hasSize(1);
        assertThat(mapped.score()).isNull();
        assertThat(mapped.severity()).isNull();
    }
}
