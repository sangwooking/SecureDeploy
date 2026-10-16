package com.securedeploy.project.coverage;

import com.securedeploy.global.error.SecureDeployException;
import org.springframework.http.HttpStatus;

public final class CoverageException extends SecureDeployException {
    private final CoverageLedger coverage;
    public CoverageException(HttpStatus status, String message, CoverageLedger coverage) {
        super(status, message);
        this.coverage = coverage;
    }
    public CoverageLedger coverage() { return coverage; }
}
