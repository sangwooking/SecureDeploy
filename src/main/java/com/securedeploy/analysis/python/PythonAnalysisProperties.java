package com.securedeploy.analysis.python;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "securedeploy.python")
public class PythonAnalysisProperties {
    private boolean enabled = true;
    private String pythonExecutable = "python3";
    private String analyzerDirectory = "analyzers/python";
    private int timeoutSeconds = 8;
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean value) { enabled = value; }
    public String getPythonExecutable() { return pythonExecutable; }
    public void setPythonExecutable(String value) { pythonExecutable = value; }
    public String getAnalyzerDirectory() { return analyzerDirectory; }
    public void setAnalyzerDirectory(String value) { analyzerDirectory = value; }
    public int getTimeoutSeconds() { return Math.max(1, Math.min(timeoutSeconds, 15)); }
    public void setTimeoutSeconds(int value) { timeoutSeconds = value; }
}
