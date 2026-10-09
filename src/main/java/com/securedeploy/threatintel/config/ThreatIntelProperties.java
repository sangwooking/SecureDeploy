package com.securedeploy.threatintel.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("securedeploy.threat-intelligence")
public record ThreatIntelProperties(@DefaultValue("true") boolean enabled,
                                    @DefaultValue("5") int timeoutSeconds,
                                    @DefaultValue("20") int budgetSeconds,
                                    @DefaultValue("300") int maxCves,
                                    @DefaultValue("21600") int cacheTtlSeconds,
                                    @DefaultValue("60") int failureBackoffSeconds,
                                    @DefaultValue("2") int epssMaxAgeDays) {
    public ThreatIntelProperties {
        timeoutSeconds = Math.max(1, Math.min(timeoutSeconds, 10));
        budgetSeconds = Math.max(1, Math.min(budgetSeconds, 30));
        maxCves = Math.max(1, Math.min(maxCves, 1000));
        cacheTtlSeconds = Math.max(60, Math.min(cacheTtlSeconds, 86400));
        failureBackoffSeconds = Math.max(10, Math.min(failureBackoffSeconds, 600));
        epssMaxAgeDays = Math.max(1, Math.min(epssMaxAgeDays, 7));
    }
}
