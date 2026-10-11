package com.securedeploy.ai.remediation;

/** A payload-free reason suitable for diagnostics without logging model/source content. */
public class RemediationValidationException extends IllegalArgumentException {
    public enum Reason { INVALID_SCHEMA, INVALID_FINDING_ID, INVALID_CONTENT, UNSUPPORTED_VERSION_REFERENCE }
    private final Reason reason;
    public RemediationValidationException(Reason reason) {
        super(reason.name());
        this.reason = reason;
    }
    public Reason reason() { return reason; }
}
