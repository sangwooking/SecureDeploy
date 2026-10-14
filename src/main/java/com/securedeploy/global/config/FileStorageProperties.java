package com.securedeploy.global.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.unit.DataSize;

@ConfigurationProperties(prefix = "securedeploy.storage")
public class FileStorageProperties {

    private String tempDir;
    private DataSize maxExpandedSize = DataSize.ofGigabytes(1);
    private int maxArchiveEntries = 50_000;
    private DataSize maxAnalysisFileSize = DataSize.ofMegabytes(32);
    private DataSize maxAnalysisTotalSize = DataSize.ofMegabytes(128);
    private int maxAnalysisLines = 500_000;

    public DataSize getMaxExpandedSize() { return maxExpandedSize; }
    public void setMaxExpandedSize(DataSize value) { maxExpandedSize = value; }
    public int getMaxArchiveEntries() { return maxArchiveEntries; }
    public void setMaxArchiveEntries(int value) { maxArchiveEntries = value; }
    public DataSize getMaxAnalysisFileSize() { return maxAnalysisFileSize; }
    public void setMaxAnalysisFileSize(DataSize value) { maxAnalysisFileSize = value; }
    public DataSize getMaxAnalysisTotalSize() { return maxAnalysisTotalSize; }
    public void setMaxAnalysisTotalSize(DataSize value) { maxAnalysisTotalSize = value; }
    public int getMaxAnalysisLines() { return maxAnalysisLines; }
    public void setMaxAnalysisLines(int value) { maxAnalysisLines = value; }

    public String getTempDir() {
        return tempDir;
    }

    public void setTempDir(String tempDir) {
        this.tempDir = tempDir;
    }
}
