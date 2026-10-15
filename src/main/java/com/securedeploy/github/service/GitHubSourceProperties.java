package com.securedeploy.github.service;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;

@Component
@ConfigurationProperties(prefix = "securedeploy.github")
public class GitHubSourceProperties {
    private int timeoutSeconds = 60;
    private int maxRequests = 12;
    private DataSize maxDownloadSize = DataSize.ofMegabytes(200);
    public int getTimeoutSeconds() { return timeoutSeconds; }
    public void setTimeoutSeconds(int value) { timeoutSeconds = value; }
    public int getMaxRequests() { return maxRequests; }
    public void setMaxRequests(int value) { maxRequests = value; }
    public DataSize getMaxDownloadSize() { return maxDownloadSize; }
    public void setMaxDownloadSize(DataSize value) { maxDownloadSize = value; }
}
