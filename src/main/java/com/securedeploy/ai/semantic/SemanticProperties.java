package com.securedeploy.ai.semantic;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "securedeploy.ai.semantic")
public class SemanticProperties {
    private int maxSlices = 4;
    private int maxContextChars = 24000;
    private int maxSnippetChars = 1800;
    private int maxOutputTokens = 4000;
    private int maxCandidates = 12;
    private int maxIndexedFiles = 200;
    private int maxIndexedChars = 2000000;
    private int maxRequests = 1;
    public int getMaxSlices() { return Math.max(1, Math.min(8, maxSlices)); }
    public void setMaxSlices(int v) { maxSlices = v; }
    public int getMaxContextChars() { return Math.max(4000, Math.min(32000, maxContextChars)); }
    public void setMaxContextChars(int v) { maxContextChars = v; }
    public int getMaxSnippetChars() { return Math.max(200, Math.min(2400, maxSnippetChars)); }
    public void setMaxSnippetChars(int v) { maxSnippetChars = v; }
    public int getMaxOutputTokens() { return Math.max(500, Math.min(6000, maxOutputTokens)); }
    public void setMaxOutputTokens(int v) { maxOutputTokens = v; }
    public int getMaxCandidates() { return Math.max(1, Math.min(20, maxCandidates)); }
    public void setMaxCandidates(int v) { maxCandidates = v; }
    public int getMaxIndexedFiles() { return Math.max(1, Math.min(300, maxIndexedFiles)); }
    public void setMaxIndexedFiles(int v) { maxIndexedFiles = v; }
    public int getMaxIndexedChars() { return Math.max(10000, Math.min(3000000, maxIndexedChars)); }
    public void setMaxIndexedChars(int v) { maxIndexedChars = v; }
    public int getMaxRequests() { return Math.max(0, Math.min(1, maxRequests)); }
    public void setMaxRequests(int v) { maxRequests = v; }
}
