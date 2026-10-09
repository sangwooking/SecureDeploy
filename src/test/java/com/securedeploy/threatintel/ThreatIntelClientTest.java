package com.securedeploy.threatintel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.threatintel.client.*;
import com.securedeploy.threatintel.model.*;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.*;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;
import static com.securedeploy.threatintel.ThreatFixtures.*;

class ThreatIntelClientTest {
    MockRestServiceServer server;
    EpssClient epss;
    CisaKevClient kev;
    MutableClock clock;
    @BeforeEach void setup() {
        var builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        var http = builder.build();
        clock = new MutableClock();
        epss = new EpssClient(http, new ObjectMapper(), properties(), clock);
        kev = new CisaKevClient(http, new ObjectMapper(), properties(), clock);
    }
    @AfterEach void verify() { server.verify(); }
    void expectEpss(String response) {
        server.expect(requestTo(EpssClient.SOURCE + "?cve=" + CVE + "&limit=1"))
                .andRespond(withSuccess(response, MediaType.APPLICATION_JSON));
    }
    @Test void epssCachesPerCveAndPreservesSourceDateAndMissingRecords() {
        expectEpss(epssJson("\"epss\":\"0.82\",\"percentile\":\"0.98\""));
        var first = epss.lookup(List.of(CVE)).get(CVE);
        assertThat(first.score()).isEqualTo(.82);
        assertThat(first.percentile()).isEqualTo(.98);
        assertThat(first.source()).isEqualTo(EpssClient.SOURCE);
        assertThat(epss.lookup(List.of(CVE, CVE)).get(CVE)).isEqualTo(first);
    }
    @Test void epssMissingCveIsNotZeroProbability() {
        expectEpss("{\"status\":\"OK\",\"total\":0,\"data\":[]}");
        var result = epss.lookup(List.of(CVE)).get(CVE);
        assertThat(result.status()).isEqualTo(LookupStatus.NOT_FOUND);
        assertThat(result.score()).isNull();
    }
    @Test void batchesRemainBelowFirstQueryLimitAndNeverRequestEveryCveIndividually() {
        List<String> ids = java.util.stream.IntStream.range(100000, 100230).mapToObj(i -> "CVE-2099-1234567890" + i).toList();
        int[] calls = {0};
        for (int i = 0; i < 4; i++) server.expect(request -> {
            String query = request.getURI().getRawQuery();
            String value = query.substring(4, query.indexOf("&limit="));
            assertThat(value.length()).isLessThanOrEqualTo(2000);
            assertThat(value.split(",").length).isGreaterThan(1);
            calls[0]++;
        }).andRespond(withSuccess("{\"status\":\"OK\",\"total\":0,\"data\":[]}", MediaType.APPLICATION_JSON));
        assertThat(epss.lookup(ids)).hasSize(230);
        assertThat(calls[0]).isEqualTo(4);
    }
    @ParameterizedTest @ValueSource(strings = {"{invalid", "{}",
            "{\"status\":\"OK\",\"total\":2,\"data\":[]}",
            "{\"status\":\"OK\",\"total\":0.5,\"data\":[]}",
            "{\"status\":\"ERROR\",\"total\":0,\"data\":[]}"})
    void invalidBatchIsUnavailable(String json) {
        expectEpss(json);
        assertThat(epss.lookup(List.of(CVE)).get(CVE).status()).isEqualTo(LookupStatus.UNAVAILABLE);
    }
    @ParameterizedTest @ValueSource(strings = {"\"epss\":\"NaN\",\"percentile\":0.9", "\"epss\":1.1,\"percentile\":0.9",
            "\"epss\":-0.1,\"percentile\":0.9", "\"epss\":0.5", "\"epss\":0.5,\"percentile\":2"})
    void invalidProbabilityIsNotAccepted(String values) {
        expectEpss(epssJson(values));
        assertThat(epss.lookup(List.of(CVE)).get(CVE).status()).isEqualTo(LookupStatus.UNAVAILABLE);
    }
    @Test void epssTimeoutUsesStalePositiveDataAndBackoff() {
        expectEpss(epssJson("\"epss\":0.82,\"percentile\":0.98"));
        server.expect(anything()).andRespond(withException(new SocketTimeoutException()));
        epss.lookup(List.of(CVE));
        clock.advance(Duration.ofHours(2));
        var stale = epss.lookup(List.of(CVE)).get(CVE);
        assertThat(stale.status()).isEqualTo(LookupStatus.STALE);
        assertThat(stale.score()).isEqualTo(.82);
        assertThat(stale.fetchedAt()).isEqualTo(NOW);
        assertThat(epss.lookup(List.of(CVE)).get(CVE)).isEqualTo(stale);
    }
    @Test void previousUtcDayDoesNotReuseFreshTtlCache() {
        clock.now = java.time.Instant.parse("2026-10-07T23:59:00Z");
        expectEpss(epssJson("\"epss\":0.8,\"percentile\":0.98"));
        expectEpss(epssJson("\"epss\":0.7,\"percentile\":0.96"));
        epss.lookup(List.of(CVE));
        clock.advance(Duration.ofMinutes(2));
        assertThat(epss.lookup(List.of(CVE)).get(CVE).score()).isEqualTo(.7);
    }
    @Test void oldEpssDatasetIsExplicitlyStaleEvenWhenFetchSucceeded() {
        expectEpss(epssJson("\"epss\":0.8,\"percentile\":0.98").replace("2026-10-07", "2026-10-01"));
        assertThat(epss.lookup(List.of(CVE)).get(CVE).status()).isEqualTo(LookupStatus.STALE);
    }
    @Test void kevDownloadsOnceAndAllowsOptionalMetadataToBeAbsent() {
        server.expect(requestTo(CisaKevClient.SOURCE)).andRespond(withSuccess(kevJson(), MediaType.APPLICATION_JSON));
        var result = kev.lookup(List.of(CVE, "CVE-2099-0002"));
        assertThat(result.get(CVE).knownExploited()).isTrue();
        assertThat(result.get(CVE).requiredAction()).isNull();
        assertThat(result.get("CVE-2099-0002").knownExploited()).isFalse();
        assertThat(kev.lookup(List.of(CVE)).get(CVE)).isEqualTo(result.get(CVE));
    }
    @Test void staleKevRetainsKnownExploitationButNeverRetainsFalseAsCurrentAbsence() {
        server.expect(anything()).andRespond(withSuccess(kevJson(), MediaType.APPLICATION_JSON));
        server.expect(anything()).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        kev.lookup(List.of(CVE));
        clock.advance(Duration.ofHours(2));
        var result = kev.lookup(List.of(CVE, "CVE-2099-0002"));
        assertThat(result.get(CVE).knownExploited()).isTrue();
        assertThat(result.get(CVE).status()).isEqualTo(LookupStatus.STALE);
        assertThat(result.get("CVE-2099-0002").knownExploited()).isNull();
        kev.lookup(List.of(CVE));
    }
    @ParameterizedTest @ValueSource(strings = {"{bad", "{}",
            "{\"dateReleased\":\"2026-10-07T11:00:00Z\",\"count\":0,\"vulnerabilities\":[]}"})
    void malformedKevCannotProduceNegativeLookup(String json) {
        server.expect(anything()).andRespond(withSuccess(json, MediaType.APPLICATION_JSON));
        var result = kev.lookup(List.of(CVE)).get(CVE);
        assertThat(result.knownExploited()).isNull();
        assertThat(result.status()).isEqualTo(LookupStatus.UNAVAILABLE);
    }
    @Test void truncatedKevCatalogDoesNotProduceFalse() {
        server.expect(anything()).andRespond(withSuccess(kevJson().replace("\"count\":1", "\"count\":2"), MediaType.APPLICATION_JSON));
        assertThat(kev.lookup(List.of(CVE)).get(CVE).knownExploited()).isNull();
    }
    @Test void oversizedIntegerCatalogCountCannotWrapIntoAValidCount() {
        server.expect(anything()).andRespond(withSuccess(kevJson().replace("\"count\":1", "\"count\":4294967297"), MediaType.APPLICATION_JSON));
        assertThat(kev.lookup(List.of(CVE)).get(CVE).status()).isEqualTo(LookupStatus.UNAVAILABLE);
    }
}
