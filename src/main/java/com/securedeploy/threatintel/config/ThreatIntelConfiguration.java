package com.securedeploy.threatintel.config;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
@EnableConfigurationProperties(ThreatIntelProperties.class)
public class ThreatIntelConfiguration {
    @Bean("threatIntelClock") Clock threatIntelClock() { return Clock.systemUTC(); }
    @Bean("threatIntelRestClient") RestClient threatIntelRestClient(ThreatIntelProperties properties) {
        var timeout = Duration.ofSeconds(properties.timeoutSeconds());
        var client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
        var factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(timeout);
        return RestClient.builder().requestFactory(factory).build();
    }
}
