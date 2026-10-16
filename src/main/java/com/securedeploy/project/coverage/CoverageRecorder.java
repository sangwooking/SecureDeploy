package com.securedeploy.project.coverage;

import java.util.*;

/** Bounded metadata only. Never stores file contents or absolute source locations. */
public final class CoverageRecorder {
    public static final int MAX_ENTRIES = 2000;
    private final List<CoverageLedger.Entry> entries = new ArrayList<>();
    private int discovered, selected, unsupported, excluded, failed, omitted;
    private boolean complete = true;

    public void record(String path, String kind, String type, String status, String reason) {
        if ("FILE".equals(kind)) {
            discovered++;
            switch (status) {
                case "SELECTED" -> selected++;
                case "UNSUPPORTED" -> unsupported++;
                case "EXCLUDED" -> excluded++;
                case "FAILED", "LIMIT_EXCEEDED" -> failed++;
                default -> { }
            }
        }
        if (entries.size() < MAX_ENTRIES) entries.add(new CoverageLedger.Entry(safePath(path), kind, type, status, reason));
        else omitted++;
    }

    public void merge(CoverageLedger previous) {
        if (previous == null) return;
        discovered += previous.discoveredFiles(); selected += previous.selectedFiles();
        unsupported += previous.unsupportedFiles(); excluded += previous.excludedFiles(); failed += previous.failedFiles();
        complete &= previous.inventoryComplete(); omitted += previous.omittedEntries();
        for (var entry : previous.entries()) {
            if (entries.size() < MAX_ENTRIES) entries.add(entry); else omitted++;
        }
    }

    public void incomplete() { complete = false; }
    public CoverageLedger snapshot() {
        return new CoverageLedger(1, "coverage-ledger-v1", failed > 0 ? "FAILED"
                : !complete || unsupported > 0 || excluded > 0 ? "PARTIAL" : "COMPLETE",
                discovered, selected, unsupported, excluded, failed, complete, omitted,
                List.copyOf(entries), List.of());
    }

    public static String safePath(String path) {
        if (path == null || path.length() > 500 || path.startsWith("/") || path.startsWith("\\")
                || path.matches("^[A-Za-z]:.*") || Arrays.asList(path.replace('\\', '/').split("/")).contains("..")
                || path.matches("(?is).*(?:[\\p{Cntrl}]|://|[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}|(?:token|secret|password|api[_-]?key)=|sk-|gh[pousr]_|AKIA).*"))
            return "[redacted-path]";
        return path.replace('\\', '/');
    }
}
