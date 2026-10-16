package com.securedeploy.analysis.typescript;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "securedeploy.typescript")
public class TypeScriptAnalysisProperties {
    private boolean enabled = true;
    private String nodeExecutable = "node";
    private String analyzerDirectory = "analyzers/typescript";
    private int timeoutSeconds = 8;
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean value) { enabled = value; }
    public String getNodeExecutable() { return nodeExecutable; }
    public void setNodeExecutable(String value) { nodeExecutable = value; }
    public String getAnalyzerDirectory() { return analyzerDirectory; }
    public void setAnalyzerDirectory(String value) { analyzerDirectory = value; }
    public int getTimeoutSeconds() { return Math.max(1, Math.min(timeoutSeconds, 15)); }
    public void setTimeoutSeconds(int value) { timeoutSeconds = value; }
}
