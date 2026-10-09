package com.securedeploy.risk.policy;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@ConfigurationProperties("securedeploy.risk.epss")
public record ThreatRiskThresholds(@DefaultValue("0.5") double blockingScore,
                                   @DefaultValue("0.95") double blockingPercentile) {
    public ThreatRiskThresholds {
        if (!Double.isFinite(blockingScore) || blockingScore <= 0 || blockingScore > 1
                || !Double.isFinite(blockingPercentile) || blockingPercentile <= 0 || blockingPercentile > 1) {
            throw new IllegalArgumentException("EPSS thresholds must be within (0, 1]");
        }
    }
    @Configuration
    @EnableConfigurationProperties(ThreatRiskThresholds.class)
    public static class Registration { }
}
