package com.securedeploy.ai.service;

/** Safe transport outcome only. Never retain provider bodies, credentials or exception causes. */
public final class AiProviderFailure extends IllegalStateException {
    public enum Kind { NOT_SENT, REFUSED, INCOMPLETE, TIMEOUT, HTTP_ERROR, INVALID_RESPONSE, UNKNOWN }
    private final Kind kind;
    private final boolean requestAttempted;
    public AiProviderFailure(Kind kind, boolean requestAttempted) {
        super("AI provider outcome: " + kind + "; no automatic retry");
        this.kind = kind;
        this.requestAttempted = requestAttempted;
    }
    public Kind kind() { return kind; }
    public boolean requestAttempted() { return requestAttempted; }
}
