package com.securedeploy.sca.config;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
@Configuration
@EnableConfigurationProperties(ScaProperties.class)
public class ScaHttpConfiguration {
    @Bean("osvRestClient")
    RestClient osvRestClient(ScaProperties properties) {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(properties.timeoutSeconds() * 1000);
        factory.setReadTimeout(properties.timeoutSeconds() * 1000);
        return RestClient.builder().baseUrl("https://api.osv.dev").requestFactory(factory).build();
    }
}
