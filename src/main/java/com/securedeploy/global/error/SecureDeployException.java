package com.securedeploy.global.error;

import org.springframework.http.HttpStatus;

public class SecureDeployException extends RuntimeException {

    private final HttpStatus status;

    public SecureDeployException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
