package com.securedeploy.sca.config;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
@ConfigurationProperties("securedeploy.sca")
public record ScaProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("5") int timeoutSeconds,
        @DefaultValue("30") int budgetSeconds,
        @DefaultValue("500") int maxQueries,
        @DefaultValue("100") int maxAdvisories
) {
    public ScaProperties {
        timeoutSeconds = Math.max(1, Math.min(timeoutSeconds, 15));
        budgetSeconds = Math.max(1, Math.min(budgetSeconds, 60));
        maxQueries = Math.max(1, Math.min(maxQueries, 2000));
        maxAdvisories = Math.max(1, Math.min(maxAdvisories, 200));
    }
}
