package com.securedeploy.global.error;

import java.time.LocalDateTime;

public record ErrorResponse(
        LocalDateTime timestamp,
        int status,
        String error,
        String message,
        com.securedeploy.project.coverage.CoverageLedger coverage
) {
    public ErrorResponse(LocalDateTime timestamp, int status, String error, String message) {
        this(timestamp, status, error, message, null);
    }
}
